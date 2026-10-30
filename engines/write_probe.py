#!/usr/bin/env python3
"""Isolated single-router ACS write probe. Changes only engineer RebootPersistent from 1 to 0, verifies, restores 1, verifies. Journal supports recovery; SSH rollback is required if interrupted and ACS cannot reconnect. Does not change Password, Enable, Access or root account."""

import json
from session_runtime import capture_session
from scapy.all import AsyncSniffer

import argparse
import base64
import hashlib
import hmac
import html
import http.client
import os
import pty
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler
from pathlib import Path

# The engines may also be invoked directly from their engines/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_network import (pppd_command, find_ppp_interface, add_acs_alias, firewall_status,
                          service_address, service_addresses, prepare_socket,
                          LabHTTPServer as ThreadingHTTPServer)

try:
    from scapy.all import Dot1Q, Ether, PPP, PPPoE, Raw, conf, get_if_hwaddr, sniff
except ImportError:
    sys.exit("scapy is required: python3 -m pip install --user scapy")

PADI, PADO, PADR, PADS, PADT = 0x09, 0x07, 0x19, 0x65, 0xA7
TAG_SERVICE, TAG_ACNAME, TAG_HOSTUNIQ, TAG_COOKIE = 0x0101, 0x0102, 0x0103, 0x0104
PROTO_LCP, PROTO_PAP, PROTO_CHAP, PROTO_IPCP, PROTO_IP, PROTO_IPV6CP = 0xC021, 0xC023, 0xC223, 0x8021, 0x0021, 0x8057

PAP_SECRETS = "/tmp/pppoe-pap-secrets"


def fcs16(data: bytes) -> int:
    fcs = 0xFFFF
    for b in data:
        fcs ^= b
        for _ in range(8):
            fcs = (fcs >> 1) ^ 0x8408 if fcs & 1 else fcs >> 1
    return fcs ^ 0xFFFF


def escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b < 0x20 or b in (0x7D, 0x7E):
            out += bytes((0x7D, b ^ 0x20))
        else:
            out.append(b)
    return bytes(out)


def unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x7D and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def hdlc_encode(ppp_frame: bytes) -> bytes:
    # pppd with noaccomp sends Address+Control; include them.
    body = b"\xff\x03" + ppp_frame
    body += fcs16(body).to_bytes(2, "little")
    return b"\x7e" + escape(body) + b"\x7e"


def hdlc_decode(buf: bytes):
    """Yield PPP frames (without 0xff03, without FCS) from an async HDLC buffer."""
    frames = []
    for chunk in buf.split(b"\x7e"):
        if len(chunk) < 4:
            continue
        raw = unescape(chunk)
        if len(raw) < 4:
            continue
        body, fcs = raw[:-2], raw[-2:]
        if fcs16(body) != int.from_bytes(fcs, "little"):
            # Still accept the frame; pppd will complain if it is bad.
            pass
        if body[:2] == b"\xff\x03":
            body = body[2:]
        if len(body) >= 2:
            frames.append(body)
    return frames


def tags_parse(data: bytes):
    out = []
    i = 0
    while i + 4 <= len(data):
        t = int.from_bytes(data[i:i + 2], "big")
        l = int.from_bytes(data[i + 2:i + 4], "big")
        v = data[i + 4:i + 4 + l]
        out.append((t, v))
        i += 4 + l
    return out


def tags_build(tags):
    out = b""
    for t, v in tags:
        out += t.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v
    return out


def ensure_pap_secrets():
    raise RuntimeError("Use runner.py: temporary PAP setup is managed there")


ACS_KEY_PATH = ""
ACS_CERT_PATH = ""
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli_write_probe.log")
CWMP_TRACE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli_write_probe_trace.log")
_CWMP_TRACE_LOCK = threading.Lock()


class Tee:
    def __init__(self, *files):
        self.files = files

    def write(self, data):
        for f in self.files:
            try:
                f.write(data)
                f.flush()
            except Exception:
                pass

    def flush(self):
        for f in self.files:
            try:
                f.flush()
            except Exception:
                pass


def _local_name(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag.split(":")[-1]


def _soap_parts(body):
    """Return (CWMP namespace, RPC name, CWMP ID, XML root) for a SOAP body."""
    root = ET.fromstring(body)
    header = next((node for node in root if _local_name(node.tag) == "Header"), None)
    soap_body = next((node for node in root if _local_name(node.tag) == "Body"), None)
    rpc = next(iter(soap_body), None) if soap_body is not None else None
    msg_id = None
    if header is not None:
        id_node = next((node for node in header if _local_name(node.tag) == "ID"), None)
        if id_node is not None:
            msg_id = id_node.text or ""
    namespace = None
    rpc_name = None
    if rpc is not None:
        rpc_name = _local_name(rpc.tag)
        if rpc.tag.startswith("{"):
            namespace = rpc.tag[1:].split("}", 1)[0]
    return namespace, rpc_name, msg_id, root


def _find_text(root, local_name):
    for node in root.iter():
        if _local_name(node.tag) == local_name:
            return node.text or ""
    return ""


def _connection_request_url(root):
    """Read the advertised Device.ManagementServer.ConnectionRequestURL."""
    for node in root.iter():
        if _local_name(node.tag) != "ParameterValueStruct":
            continue
        name = next((child.text or "" for child in node
                     if _local_name(child.tag) == "Name"), "")
        if name != "Device.ManagementServer.ConnectionRequestURL":
            continue
        return next((child.text or "" for child in node
                     if _local_name(child.tag) == "Value"), "")
    return ""


def _connection_request_target(url, peer_ip):
    """Only allow the exact advertised HTTP endpoint on this CPE's PPP peer."""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (parsed.scheme.lower() != "http" or host != peer_ip or port != 7547
            or parsed.username is not None or parsed.password is not None):
        return None
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, path


def _envelope(ns, inner, msg_id=None):
    header = ""
    if msg_id is not None:
        header = ('<cwmp:ID soapenv:mustUnderstand="1">%s</cwmp:ID>'
                  % html.escape(str(msg_id), quote=True))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<soapenv:Envelope soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" '
        'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:soap="http://schemas.xmlsoap.org/soap/encoding/" '
        'xmlns:cwmp="%s" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/">'
        "<soapenv:Header>%s</soapenv:Header><soapenv:Body>%s</soapenv:Body></soapenv:Envelope>"
        % (ns, header, inner)
    ).encode("utf-8")


def _inform_response(ns, msg_id):
    return _envelope(
        ns,
        "<cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse>",
        msg_id,
    )


def _get_rpc_methods(ns, msg_id):
    return _envelope(ns, "<cwmp:GetRPCMethods/>", msg_id)


def _get_parameter_names(ns, msg_id, path):
    inner = (
        "<cwmp:GetParameterNames><ParameterPath>%s</ParameterPath>"
        "<NextLevel>0</NextLevel></cwmp:GetParameterNames>"
        % html.escape(path, quote=True)
    )
    return _envelope(ns, inner, msg_id)


def _get_parameter_values(ns, msg_id, paths):
    values = "".join("<string>%s</string>" % html.escape(path, quote=True) for path in paths)
    inner = (
        "<cwmp:GetParameterValues>"
        '<ParameterNames soap:arrayType="xsd:string[%d]">%s</ParameterNames>'
        "</cwmp:GetParameterValues>" % (len(paths), values)
    )
    return _envelope(ns, inner, msg_id)



PROBE_BASE = "Device.Services.X_000E50_AccessManagement.SSH.CliUsers.1."
PROBE_PATH = PROBE_BASE + "RebootPersistent"
PROBE_JOURNAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "write_probe_state.json")

def _read_probe_journal():
    try:
        with open(PROBE_JOURNAL) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def _save_probe_journal(data):
    fd = os.open(PROBE_JOURNAL, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())

def _set_probe_value(ns, msg_id, value):
    if value not in ("0", "1"):
        raise ValueError("Probe permits only boolean RebootPersistent writes")
    inner = ('<cwmp:SetParameterValues><ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[1]">'
             '<ParameterValueStruct><Name>' + PROBE_PATH + '</Name><Value xsi:type="xsd:boolean">' + value +
             '</Value></ParameterValueStruct></ParameterList><ParameterKey></ParameterKey></cwmp:SetParameterValues>')
    return _envelope(ns, inner, msg_id)

class ACSState:
    """Single-CPE, read-only CWMP diagnostic session state."""

    def __init__(self, auth_user="ftacs", auth_password="ftacs", require_auth=True,
                 cr_user="ftacs", cr_password="ftacs"):
        self.lock = threading.RLock()
        self.stage = "waiting_inform"
        self.namespace = None
        self.pending_id = None
        self.message_number = 0
        self.auth_user = auth_user
        self.auth_password = auth_password
        self.require_auth = require_auth
        self.auth_nonces = {}
        self.cr_user = cr_user
        self.cr_password = cr_password
        self.connection_probe_claimed = False

    def next_id(self):
        with self.lock:
            self.message_number += 1
            return "lab-%d" % self.message_number

    def new_nonce(self):
        nonce = os.urandom(16).hex()
        with self.lock:
            now = time.time()
            self.auth_nonces = {key: expires for key, expires in self.auth_nonces.items()
                                if expires > now}
            self.auth_nonces[nonce] = now + 300
        return nonce

    def claim_connection_probe(self):
        with self.lock:
            if self.connection_probe_claimed:
                return False
            self.connection_probe_claimed = True
            return True

    def authenticate(self, header, method, uri):
        if not self.require_auth:
            return True, "disabled"
        if not header:
            return False, "missing Authorization"
        scheme, _, credentials = header.partition(" ")
        if scheme.lower() == "basic":
            try:
                decoded = base64.b64decode(credentials.strip(), validate=True).decode("utf-8")
                username, separator, password = decoded.partition(":")
            except (ValueError, UnicodeDecodeError):
                return False, "malformed Basic credentials"
            valid = (separator and hmac.compare_digest(username, self.auth_user)
                     and hmac.compare_digest(password, self.auth_password))
            return bool(valid), "Basic" if valid else "invalid Basic credentials"

        if scheme.lower() != "digest":
            return False, "unsupported Authorization scheme"
        params = {}
        for match in re.finditer(r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:\\.|[^"])*)"|([^,\s]+))', credentials):
            value = match.group(2) if match.group(2) is not None else match.group(3)
            params[match.group(1).lower()] = re.sub(r'\\([\\"])', r'\1', value)
        required = ("username", "realm", "nonce", "uri", "response")
        if any(not params.get(key) for key in required):
            return False, "incomplete Digest credentials"
        if (params["username"] != self.auth_user or params["realm"] != "acs"
                or params["uri"] != uri):
            return False, "Digest identity/URI mismatch"
        with self.lock:
            expires = self.auth_nonces.get(params["nonce"])
        if not expires or expires < time.time():
            return False, "unknown/expired Digest nonce"
        algorithm = params.get("algorithm", "MD5").upper()
        if algorithm not in ("MD5", "MD5-SESS"):
            return False, "unsupported Digest algorithm"
        ha1 = hashlib.md5(("%s:%s:%s" %
                           (self.auth_user, "acs", self.auth_password)).encode()).hexdigest()
        qop = params.get("qop", "").lower()
        if algorithm == "MD5-SESS":
            cnonce = params.get("cnonce", "")
            if not cnonce:
                return False, "Digest MD5-sess lacks cnonce"
            ha1 = hashlib.md5(("%s:%s:%s" % (ha1, params["nonce"], cnonce)).encode()).hexdigest()
        ha2 = hashlib.md5(("%s:%s" % (method, uri)).encode()).hexdigest()
        if qop == "auth":
            nc, cnonce = params.get("nc", ""), params.get("cnonce", "")
            if not nc or not cnonce:
                return False, "Digest qop=auth lacks nc/cnonce"
            expected = hashlib.md5(("%s:%s:%s:%s:auth:%s" %
                                    (ha1, params["nonce"], nc, cnonce, ha2)).encode()).hexdigest()
        elif not qop:
            expected = hashlib.md5(("%s:%s:%s" % (ha1, params["nonce"], ha2)).encode()).hexdigest()
        else:
            return False, "unsupported Digest qop"
        valid = hmac.compare_digest(expected.lower(), params["response"].lower())
        return valid, "Digest" if valid else "invalid Digest response"


def _trace_cwmp(direction, peer, details, body=b""):
    """Append raw SOAP bodies to a mode-0600 local trace, never to the console."""
    record = (
        "\n--- %s %s peer=%s %s ---\n"
        % (time.strftime("%Y-%m-%d %H:%M:%S"), direction, peer, details)
    ).encode("utf-8") + body + b"\n"
    with _CWMP_TRACE_LOCK:
        fd = os.open(CWMP_TRACE_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "ab", closefd=False) as trace:
                trace.write(record)
                trace.flush()
        finally:
            os.close(fd)


class ACSHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lab-acs/1.0"

    def log_message(self, fmt, *args):
        print("[acs:%d] %s" % (getattr(self.server, "server_port", 0), fmt % args))

    def handle_expect_100(self):
        # Let do_POST emit exactly one interim response after recording headers.
        return True

    def _send(self, code, body=b""):
        self.send_response(code)
        if body:
            self.send_header("Content-Type", 'text/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(body)))
        connection = (self.headers.get("Connection", "") or "").lower()
        if self.close_connection or "close" in connection:
            self.close_connection = True
        else:
            self.close_connection = False
        self.end_headers()
        if body:
            self.wfile.write(body)
        _trace_cwmp("OUT", self.client_address[0], "HTTP %d" % code, body)

    def do_GET(self):
        print("[acs:%d] GET %s" % (self.server.server_port, self.path))
        self._send(200, b"lab-acs")

    def _read_body(self):
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            data = bytearray()
            while True:
                line = self.rfile.readline(128).strip()
                if not line:
                    raise ValueError("missing chunk-size line")
                try:
                    size = int(line.split(b";")[0], 16)
                except ValueError:
                    raise ValueError("invalid chunk-size line %r" % line[:80])
                if size == 0:
                    # Consume optional trailer headers through the terminating CRLF.
                    while self.rfile.readline(8192) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                if len(data) + size > 4 * 1024 * 1024:
                    raise ValueError("CWMP body exceeds 4 MiB diagnostic limit")
                chunk = self.rfile.read(size)
                if len(chunk) != size:
                    raise ValueError("truncated HTTP chunk")
                data.extend(chunk)
                if self.rfile.read(2) != b"\r\n":
                    raise ValueError("missing CRLF after HTTP chunk")
            return bytes(data)
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n > 4 * 1024 * 1024:
            raise ValueError("CWMP body exceeds 4 MiB diagnostic limit")
        body = self.rfile.read(n) if n else b""
        if len(body) != n:
            raise ValueError("truncated HTTP body")
        return body

    def _send_continue(self):
        self.send_response_only(100)
        self.end_headers()
        print("[acs] sent one 100 Continue")

    def _send_auth_challenge(self):
        nonce = self.server.state.new_nonce()
        self.send_response(401)
        self.send_header(
            "WWW-Authenticate",
            'Digest realm="acs", nonce="%s", qop="auth", algorithm=MD5' % nonce,
        )
        self.send_header("WWW-Authenticate", 'Basic realm="acs"')
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        print("[acs] sent Digest/Basic challenge (credentials are not logged)")
        _trace_cwmp("OUT", self.client_address[0], "HTTP 401 Digest/Basic challenge")

    def _probe_connection_request(self, url, peer_ip):
        """Probe the advertised URL, then answer one Digest challenge if offered."""
        target = _connection_request_target(url, peer_ip)
        if target is None:
            print("[cwmp] Connection Request probe skipped: URL is not the peer's HTTP:7547 endpoint")
            return
        if not self.server.state.claim_connection_probe():
            return
        host, port, path = target
        # Let the boot Inform/empty-POST exchange settle before triggering a
        # separate CPE-initiated session via its Connection Request listener.
        time.sleep(2)
        challenge_headers = []
        conn = http.client.HTTPConnection(host, port, timeout=3)
        try:
            # First request is deliberately unauthenticated so we can obtain the
            # CPE's Digest challenge. Keep HTTP/1.1 alive so the authenticated
            # retry can reuse the challenge connection if the CPE permits it.
            conn.request("GET", path, headers={
                "User-Agent": "cwmp-readonly-diagnostic/1.0",
            })
            response = conn.getresponse()
            response.read()
            challenge_connection = response.getheader("Connection", "(default keep-alive)")
            same_tcp_available = conn.sock is not None
            for name, value in response.getheaders():
                if name.lower() != "www-authenticate":
                    continue
                challenge_headers.append(value)
            challenge_summary = self._summarize_challenges(challenge_headers)
            print("[cwmp] unauthenticated Connection Request probe -> HTTP %d; challenge=%s"
                  % (response.status, challenge_summary))
            if response.status == 200:
                print("[cwmp] endpoint accepted unauthenticated GET; no extra request sent")
            _trace_cwmp(
                "CR-PROBE", host,
                "GET <advertised-token-path> -> HTTP %d challenge=%s connection=%s same_tcp=%s"
                % (response.status, challenge_summary, challenge_connection, same_tcp_available),
            )
            if response.status != 401:
                conn.close()
                return
            digest = next((value for value in challenge_headers
                           if value.lower().startswith("digest ")), None)
            if digest is None:
                print("[cwmp] no Digest challenge; credentials not sent")
                conn.close()
                return
            authorization = self._connection_request_digest(digest, path)
            if authorization is None:
                print("[cwmp] unsupported/incomplete Digest challenge; credentials not sent")
                conn.close()
                return
        except (OSError, http.client.HTTPException) as exc:
            print("[cwmp] Connection Request probe failed: %s" % exc)
            _trace_cwmp("CR-PROBE", host, "GET <advertised-token-path> failed: %s" % exc)
            conn.close()
            return

        # One authenticated GET only. This may trigger a fresh Inform, but it
        # cannot change a parameter; never send Basic credentials or retry again.
        try:
            same_tcp = conn.sock is not None
            conn.request("GET", path, headers={
                "Authorization": authorization,
                "User-Agent": "cwmp-readonly-diagnostic/1.0",
            })
            auth_response = conn.getresponse()
            auth_response.read()
            next_challenges = [value for name, value in auth_response.getheaders()
                               if name.lower() == "www-authenticate"]
            next_summary = self._summarize_challenges(next_challenges)
            print("[cwmp] Digest-authenticated Connection Request -> HTTP %d (same TCP=%s)"
                  % (auth_response.status, same_tcp))
            if auth_response.status == 200:
                print("[cwmp] Connection Request accepted; CPE may open a fresh Inform session")
            elif auth_response.status == 401:
                print("[cwmp] Digest credentials rejected; challenge=%s" % next_summary)
            _trace_cwmp(
                "CR-AUTH", host,
                "Digest GET <advertised-token-path> -> HTTP %d challenge=%s same_tcp=%s response_sha256=%s"
                % (auth_response.status, next_summary, same_tcp,
                   hashlib.sha256(authorization.encode()).hexdigest()[:16]),
            )
        except (OSError, http.client.HTTPException) as exc:
            print("[cwmp] authenticated Connection Request failed: %s" % exc)
            _trace_cwmp("CR-AUTH", host, "Digest GET <advertised-token-path> failed: %s" % exc)
        finally:
            conn.close()

    @staticmethod
    def _summarize_challenges(challenges):
        summaries = []
        for value in challenges:
            scheme = value.split(None, 1)[0] if value else "unknown"
            realm = re.search(r'realm="([^"]*)"', value, re.I)
            qop = re.search(r'qop="?([^", ]+)', value, re.I)
            summary = scheme
            if realm:
                summary += '(realm="%s")' % realm.group(1)
            if qop:
                summary += '(qop=%s)' % qop.group(1)
            algorithm = re.search(r'algorithm="?([^", ]+)', value, re.I)
            if algorithm:
                summary += '(algorithm=%s)' % algorithm.group(1)
            if re.search(r'opaque=', value, re.I):
                summary += '(opaque=yes)'
            if re.search(r'stale=true', value, re.I):
                summary += '(stale=true)'
            summaries.append(summary)
        return ",".join(summaries) if summaries else "none"

    def _connection_request_digest(self, challenge, uri):
        scheme, _, params_text = challenge.partition(" ")
        if scheme.lower() != "digest":
            return None
        params = {}
        pattern = r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:\\.|[^"])*)"|([^,\s]+))'
        for match in re.finditer(pattern, params_text):
            value = match.group(2) if match.group(2) is not None else match.group(3)
            params[match.group(1).lower()] = re.sub(r'\\([\\"])', r'\1', value)
        realm, nonce = params.get("realm"), params.get("nonce")
        qops = [item.strip().lower() for item in params.get("qop", "").split(",")]
        if not realm or not nonce or "auth" not in qops:
            return None
        algorithm = params.get("algorithm", "MD5").upper()
        if algorithm not in ("MD5", "MD5-SESS"):
            return None
        user = self.server.state.cr_user
        password = self.server.state.cr_password
        nc, cnonce, qop = "00000001", os.urandom(8).hex(), "auth"
        ha1 = hashlib.md5(("%s:%s:%s" % (user, realm, password)).encode()).hexdigest()
        if algorithm == "MD5-SESS":
            ha1 = hashlib.md5(("%s:%s:%s" % (ha1, nonce, cnonce)).encode()).hexdigest()
        ha2 = hashlib.md5(("GET:%s" % uri).encode()).hexdigest()
        digest = hashlib.md5(("%s:%s:%s:%s:%s:%s" %
                              (ha1, nonce, nc, cnonce, qop, ha2)).encode()).hexdigest()
        header = (
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", '
            'response="%s", algorithm=%s, qop=%s, nc=%s, cnonce="%s"'
            % (user, realm, nonce, uri, digest, algorithm, qop, nc, cnonce)
        )
        if params.get("opaque") is not None:
            header += ', opaque="%s"' % params["opaque"]
        return header

    def _record_request(self, raw_body):
        # Exclude Authorization/Cookie headers; record only CWMP framing metadata.
        selected = ("Content-Length", "Transfer-Encoding", "Expect", "Content-Type",
                    "SOAPAction", "Connection")
        safe_headers = ", ".join(
            "%s=%r" % (name, self.headers.get(name))
            for name in selected if self.headers.get(name) is not None
        )
        _trace_cwmp(
            "IN", self.client_address[0], "POST %s %s" % (self.path, safe_headers), raw_body
        )

    def _check_response_id(self, received_id, rpc_name):
        expected = self.server.state.pending_id
        if expected is None:
            print("[acs] %s arrived with no outstanding ACS RPC (ID=%r)" % (rpc_name, received_id))
        elif received_id != expected:
            print("[acs] WARNING %s ID mismatch: expected %r, got %r"
                  % (rpc_name, expected, received_id))
        else:
            print("[acs] %s echoed CWMP ID %r" % (rpc_name, received_id))
        self.server.state.pending_id = None

    def _handle_inform(self, namespace, msg_id, root):
        st = self.server.state
        namespace = namespace or "urn:dslforum-org:cwmp-1-2"
        if not msg_id:
            print("[acs] WARNING Inform has no CWMP ID; using a diagnostic fallback")
            msg_id = st.next_id()
        st.namespace = namespace
        st.stage = "await_inform_poll"
        serial = _find_text(root, "SerialNumber")
        print("[acs] Inform from %s; CWMP namespace=%s ID=%r" % (serial or "?", namespace, msg_id))
        cr_url = _connection_request_url(root)
        self._send(200, _inform_response(namespace, msg_id))
        print("[cwmp] Connection Request probe disabled for this CLI read-only test")

    def _handle_get_names_response(self, root, received_id):
        st = self.server.state
        self._check_response_id(received_id, "GetParameterNamesResponse")
        candidates = []
        for node in root.iter():
            if _local_name(node.tag) != "ParameterInfoStruct":
                continue
            name = next((child.text or "" for child in node
                         if _local_name(child.tag) == "Name"), "")
            writable = next((child.text or "" for child in node
                             if _local_name(child.tag) == "Writable"), "")
            if name.startswith("Device.Services.X_000E50_AccessManagement.SSH.CliUsers.") and name.rsplit(".", 1)[-1] in {"Username", "Enable", "Access", "RebootPersistent"}:
                candidates.append((name, writable))
        print("[acs] GetParameterNamesResponse: %d CLI user candidate(s)" % len(candidates))
        for name, writable in candidates:
            print("[acs] candidate %s Writable=%s" % (name, writable or "(omitted)"))
        if not candidates:
            st.stage = "complete_read_only"
            self._send(204)
            return

        # Query the actual values, but do not change any device parameter.
        paths = [name for name, _ in candidates[:128]]
        next_id = st.next_id()
        st.pending_id = next_id
        st.stage = "await_get_values_response"
        print("[acs] GetParameterValues for %d discovered CLI user path(s), ID=%r"
              % (len(paths), next_id))
        self._send(200, _get_parameter_values(st.namespace, next_id, paths))

    def _handle_rpc_methods_response(self, root, received_id):
        st = self.server.state
        self._check_response_id(received_id, "GetRPCMethodsResponse")
        methods = [node.text or "" for node in root.iter() if _local_name(node.tag) == "string"]
        print("[acs] GetRPCMethodsResponse listed %d method(s); GetParameterNames=%s"
              % (len(methods), "yes" if "GetParameterNames" in methods else "no"))
        if "GetParameterNames" not in methods:
            st.stage = "complete_read_only"
            self._send(204)
            return
        next_id = st.next_id()
        st.pending_id = next_id
        st.stage = "await_get_names_response"
        print("[acs] sending read-only GetParameterNames Device.Services.X_000E50_AccessManagement.SSH.CliUsers. ID=%r" % next_id)
        self._send(200, _get_parameter_names(st.namespace, next_id, "Device.Services.X_000E50_AccessManagement.SSH.CliUsers."))

    def _probe_send(self, value=None, stage=None):
        st = self.server.state
        msg_id = st.next_id()
        st.pending_id = msg_id
        st.stage = stage
        if value is None:
            body = _get_parameter_values(st.namespace, msg_id, [PROBE_PATH])
        else:
            body = _set_probe_value(st.namespace, msg_id, value)
            print('[write-test] SetParameterValues RebootPersistent=%s stage=%s' % (value, stage))
        self._send(200, body)

    def _handle_get_values_response(self, root, received_id):
        st = self.server.state
        if received_id != st.pending_id:
            print('[write-test] ID mismatch; stopping, inspect rollback journal')
            self._send(204)
            return
        values = {}
        for node in root.iter():
            if _local_name(node.tag) == 'ParameterValueStruct':
                name = next((c.text or '' for c in node if _local_name(c.tag) == 'Name'), '')
                value = next((c.text or '' for c in node if _local_name(c.tag) == 'Value'), '')
                values[name] = value
                if name.startswith(PROBE_BASE) and name.rsplit('.', 1)[-1] in ('Username','Enable','Access','RebootPersistent'):
                    print('[acs] current value %s = %r' % (name, value))
        current = values.get(PROBE_PATH)
        normalized = {'true':'1', 'false':'0', '1':'1', '0':'0'}.get(current)
        journal = _read_probe_journal()
        if st.stage == 'probe_verify_toggle':
            confirmed = normalized == '0'
            journal['toggle_verified'] = confirmed
            _save_probe_journal(journal)
            print('[write-test] changed value readback=%r verified=%s; restoring original now' % (current, confirmed))
            self._probe_send('1', 'probe_restore')
        elif st.stage == 'probe_verify_restore':
            if normalized == '1':
                journal['status'] = 'restored'
                _save_probe_journal(journal)
                print('[write-test] WRITE_TEST_PASS_RESTORED' if journal.get('toggle_verified') else '[write-test] RESTORED_BUT_TOGGLE_NOT_PROVEN')
            else:
                print('[write-test] RESTORE_UNCONFIRMED: use documented SSH rollback')
            st.stage = 'probe_done'
            self._send(204)
        elif st.stage == 'await_get_values_response':
            if journal.get('status') == 'pending':
                print('[write-test] recovering interrupted test; restoring original value')
                self._probe_send('1', 'probe_restore')
            elif journal:
                print('[write-test] prior attempt recorded; not repeating writes')
                self._send(204)
            elif (values.get(PROBE_BASE+'Username') == 'engineer'
                  and values.get(PROBE_BASE+'Enable') in ('0','false')
                  and values.get(PROBE_BASE+'Access') == 'NONE' and normalized == '1'):
                _save_probe_journal({'status':'pending','path':PROBE_PATH,'original':'1','toggle_verified':False})
                self._probe_send('0', 'probe_toggle')
            else:
                print('[write-test] baseline differs or incomplete; no write sent')
                self._send(204)
        else:
            print('[write-test] unexpected stage; no write sent')
            self._send(204)

    def _handle_set_response(self, root, received_id):
        st = self.server.state
        if received_id != st.pending_id:
            print('[write-test] response ID mismatch; rollback remains pending')
            self._send(204)
            return
        print('[write-test] SetParameterValuesResponse status=%r' % _find_text(root, 'Status'))
        if st.stage == 'probe_toggle':
            self._probe_send(stage='probe_verify_toggle')
        elif st.stage == 'probe_restore':
            self._probe_send(stage='probe_verify_restore')
        else:
            self._send(204)

    def do_POST(self):
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        expect = (self.headers.get("Expect") or "").lower()
        # Send an interim response only when explicitly requested by the client.
        # Transfer-Encoding alone does not request 100 Continue.
        if "100-continue" in expect:
            self._send_continue()
        print("[acs:%d] hdr CL=%r TE=%r Expect=%r Auth=%r CT=%r" % (
            self.server.server_port,
            self.headers.get("Content-Length"),
            self.headers.get("Transfer-Encoding"),
            self.headers.get("Expect"),
            bool(self.headers.get("Authorization")),
            self.headers.get("Content-Type"),
        ))
        try:
            raw_body = self._read_body()
        except (OSError, ValueError) as exc:
            print("[acs] HTTP body read failed: %s" % exc)
            self.close_connection = True
            self._send(400)
            return
        self._record_request(raw_body)
        st = self.server.state
        print("[acs:%d] POST %s (%d bytes), stage=%s"
              % (self.server.server_port, self.path, len(raw_body), st.stage))

        auth_ok, auth_result = st.authenticate(
            self.headers.get("Authorization"), "POST", self.path
        )
        if not auth_ok:
            print("[acs] HTTP authentication required: %s" % auth_result)
            self._send_auth_challenge()
            return
        if st.require_auth:
            print("[acs] HTTP authentication accepted: %s" % auth_result)

        if not raw_body.strip():
            if st.stage == "await_inform_poll":
                msg_id = st.next_id()
                st.pending_id = msg_id
                st.stage = "await_rpc_methods_response"
                print("[acs] sending read-only GetRPCMethods ID=%r" % msg_id)
                self._send(200, _get_rpc_methods(st.namespace, msg_id))
            else:
                self._send(204)
            return

        try:
            namespace, rpc_name, msg_id, root = _soap_parts(raw_body)
        except ET.ParseError as exc:
            print("[acs] malformed SOAP/XML: %s" % exc)
            self._send(204)
            return

        if namespace:
            st.namespace = namespace
        print("[acs] received RPC=%s namespace=%s ID=%r"
              % (rpc_name or "?", namespace or st.namespace, msg_id))

        if rpc_name == "Inform":
            self._handle_inform(namespace, msg_id, root)
        elif rpc_name == "GetRPCMethodsResponse":
            self._handle_rpc_methods_response(root, msg_id)
        elif rpc_name == "GetParameterNamesResponse":
            self._handle_get_names_response(root, msg_id)
        elif rpc_name == "GetParameterValuesResponse":
            self._handle_get_values_response(root, msg_id)
        elif rpc_name == "SetParameterValuesResponse":
            self._handle_set_response(root, msg_id)
        elif rpc_name == "Fault":
            if hasattr(self, '_handle_profile_fault'):
                self._handle_profile_fault(root, msg_id)
                return
            self._check_response_id(msg_id, "Fault")
            fault_code = _find_text(root, "FaultCode")
            fault_string = _find_text(root, "FaultString")
            print("[acs] CPE SOAP Fault code=%r string=%r" % (fault_code, fault_string))
            if self.server.state.stage in ('probe_toggle', 'probe_verify_toggle'):
                self._probe_send('1', 'probe_restore')
            else:
                print('[write-test] fault; check journal and SSH rollback before concluding')
                self.server.state.stage = 'complete_fault'
                self._send(204)
        else:
            print("[acs] unexpected/unsupported RPC %r; no device write performed" % rpc_name)
            self._send(204)


class ACSServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def verify_request(self, request, address):
        return address[0] == getattr(self, "allowed_peer", address[0])

    def __init__(self, addr, state):
        super().__init__(addr, ACSHandler)
        self.state = state


class Bridge:
    def __init__(self, args):
        self.args = args
        self.iface = args.iface
        self.vlan = args.vlan
        self.peer_mac = args.peer_mac.lower()
        self.our_mac = get_if_hwaddr(args.iface)
        self.session = None
        self.stop = threading.Event()
        self.pty_master = None
        self.pppd = None
        self.ppp_name = 'acs' + os.urandom(5).hex()
        self.pppd_buf = b""
        self.rx_pending = []  # (proto, payload) from the CPE before pppd is ready
        self.tx_queue = queue.Queue()
        self.tx_sock = None
        self.servers_started = False

    # ---------- PPPoE ----------
    def send_pppoe(self, code, session, tags=b"", proto=None, payload=b""):
        discovery = code in (PADI, PADO, PADR, PADS, PADT)
        # PPPoE discovery must use EtherType 0x8863, session 0x8864.
        dot1q = Dot1Q(vlan=self.vlan, type=0x8863 if discovery else 0x8864)
        pkt = Ether(src=self.our_mac, dst=self.peer_mac) / dot1q / PPPoE(code=code, sessionid=session)
        if discovery:
            pkt = pkt / Raw(tags)
        else:
            pkt = pkt / PPP(proto=proto) / Raw(payload)
        self.tx_queue.put(pkt)

    def tx_loop(self):
        while not self.stop.is_set():
            try:
                pkt = self.tx_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self.tx_sock.send(pkt)
            except Exception as e:
                print("[tx] send error: %s" % e)

    def on_packet(self, pkt):
        if self.stop.is_set():
            return
        if Dot1Q not in pkt or pkt[Dot1Q].vlan != self.vlan:
            return
        if pkt[Ether].src.lower() != self.peer_mac:
            return

        # Parse PPPoE by hand: Scapy 2.8 does not always bind the PPPoE
        # layer for the discovery EtherType 0x8863.
        raw = bytes(pkt)
        off = 18  # 14 Ethernet + 4 VLAN
        if len(raw) < off + 6:
            return
        code = raw[off + 1]
        sid = int.from_bytes(raw[off + 2:off + 4], "big")
        plen = int.from_bytes(raw[off + 4:off + 6], "big")
        body = raw[off + 6:off + 6 + plen]

        etype = pkt[Dot1Q].type
        if etype == 0x8863:
            tags = tags_parse(body)
            service = b""
            hostuniq = b""
            for t, v in tags:
                if t == TAG_SERVICE:
                    service = v
                elif t == TAG_HOSTUNIQ:
                    hostuniq = v
            if code == PADI:
                print("[pppoe] PADI (service=%r hostuniq=%s)" % (service, hostuniq.hex()))
                # RFC 2516 order: Service-Name, AC-Name, Host-Uniq.
                out = [(TAG_SERVICE, service), (TAG_ACNAME, b"mac-ac"), (TAG_HOSTUNIQ, hostuniq)]
                print("[pppoe] TX PADO tags=%s" % tags_build(out).hex())
                self.send_pppoe(PADO, 0, tags_build(out))
            elif code == PADR:
                newsid = 0x1234
                out = [(TAG_SERVICE, service), (TAG_HOSTUNIQ, hostuniq)]
                print("[pppoe] PADR -> PADS session=0x%04x" % newsid)
                # Start pppd now: it must not time out while we wait for PADI.
                if self.pppd is None or self.pppd.poll() is not None:
                    self.start_pppd()
                self.session = newsid
                self.send_pppoe(PADS, newsid, tags_build(out))
                # Flush any CPE LCP frames that arrived before pppd was ready.
                if self.pty_master is not None:
                    for proto, payload in self.rx_pending:
                        self.write_pty(proto.to_bytes(2, "big") + payload)
                    self.rx_pending = []
            elif code == PADT:
                print("[pppoe] PADT")
                self.session = None
                self.stop_pppd()
        elif etype == 0x8864:
            if self.session is None or sid != self.session:
                return
            if len(body) < 2:
                return
            proto = int.from_bytes(body[:2], "big")
            payload = body[2:]
            self.log_ppp(proto, payload)
            if self.pty_master is None or self.pppd is None or self.pppd.poll() is not None:
                self.rx_pending.append((proto, payload))
            else:
                self.write_pty(proto.to_bytes(2, "big") + payload)

    def log_ppp(self, proto, body):
        if proto == PROTO_LCP and len(body) >= 4:
            code = body[0]
            names = {1: "ConfReq", 2: "ConfAck", 3: "ConfNak", 4: "ConfRej", 5: "TermReq", 6: "TermAck", 7: "CodeRej", 8: "ProtoRej", 9: "EchoReq", 10: "EchoRep"}
            print("[lcp] %s id=%d len=%d" % (names.get(code, hex(code)), body[1], len(body)))
        elif proto == PROTO_PAP and len(body) >= 4:
            code = body[0]
            if code == 1:  # Authenticate-Request
                plen = body[4]
                peer = body[5:5 + plen]
                rest = body[5 + plen:]
                if rest:
                    pwlen = rest[0]
                    pw = rest[1:1 + pwlen]
                    print("[pap] REQUEST user=%r (password redacted; %d bytes)"
                          % (peer.decode("latin1"), len(pw)))
            else:
                print("[pap] code=%d" % code)
        elif proto == PROTO_CHAP:
            print("[chap] len=%d" % len(body))

    # ---------- pty / pppd ----------
    def write_pty(self, ppp_frame):
        master = self.pty_master
        if self.stop.is_set() or master is None or self.pppd is None or self.pppd.poll() is not None:
            return
        try:
            data = hdlc_encode(ppp_frame)
            while data and not self.stop.is_set():
                n = os.write(master, data)
                if n <= 0:
                    break
                data = data[n:]
        except OSError as e:
            if not self.stop.is_set():
                print("[pty] write error: %s" % e)

    def read_pty(self):
        while not self.stop.is_set():
            master = self.pty_master
            if master is None:
                time.sleep(0.05)
                continue
            try:
                data = os.read(master, 4096)
            except OSError:
                # EIO is normal until pppd has opened the slave side.
                if self.stop.is_set() or (self.pppd is not None and self.pppd.poll() is not None):
                    break
                time.sleep(0.05)
                continue
            if not data:
                time.sleep(0.05)
                continue
            self.pppd_buf += data
            # keep the last incomplete chunk after the final flag
            parts = self.pppd_buf.split(b"\x7e")
            if len(parts) > 1:
                for frame in hdlc_decode(b"\x7e".join(parts[:-1]) + b"\x7e"):
                    if len(frame) < 2:
                        continue
                    proto = int.from_bytes(frame[:2], "big")
                    if proto in (PROTO_LCP, PROTO_PAP, PROTO_CHAP, PROTO_IPCP, PROTO_IP, PROTO_IPV6CP):
                        self.log_ppp(proto, frame[2:])
                        if self.session is not None:
                            self.send_pppoe(0x00, self.session, proto=proto, payload=frame[2:])
                        else:
                            print("[bridge] pppd frame before PPPoE session, dropped (proto=0x%04x)" % proto)
                self.pppd_buf = parts[-1]

    def pppd_reader(self):
        if not self.pppd:
            return
        for line in self.pppd.stdout:
            print("[pppd] " + line.decode("utf-8", "replace").rstrip())

    def start_pppd(self):
        ensure_pap_secrets()
        # monitor_ppp adds the ACS alias to this run's PPP interface.
        # Do not overwrite the system-wide /etc/ppp/ip-up hook.
        master, slave = pty.openpty()
        slave_name = os.ttyname(slave)
        os.close(slave)
        self.pty_master = master
        cmd = pppd_command(slave_name, self.args.local_ip,
                            self.args.peer_ip, self.ppp_name)
        print("[pppd] %s" % " ".join(cmd))
        self.pppd = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        threading.Thread(target=self.pppd_reader, daemon=True).start()
        threading.Thread(target=self.read_pty, daemon=True).start()
        # Flush CPE frames that arrived before pppd was ready.
        for proto, payload in self.rx_pending:
            self.write_pty(proto.to_bytes(2, "big") + payload)
        self.rx_pending = []

    def stop_pppd(self):
        if self.pppd is not None:
            try:
                self.pppd.terminate()
                self.pppd.wait(timeout=2)
            except Exception:
                try:
                    self.pppd.kill()
                except Exception:
                    pass
            self.pppd = None
        if self.pty_master is not None:
            try:
                os.close(self.pty_master)
            except (OSError, KeyboardInterrupt):
                pass
            self.pty_master = None

    def dns_loop(self, stop):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            prepare_socket(s)
            s.bind((service_address(self.args.local_ip), 53))
        except OSError as e:
            print("[dns] bind failed: %s" % e)
            return
        s.settimeout(0.5)
        print("[dns] listening on %s:53" % service_address(self.args.local_ip))
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] != self.args.peer_ip:
                continue
            if len(data) < 12:
                continue
            tid = data[:2]
            # question name
            i = 12
            labels = []
            while i < len(data) and data[i] != 0:
                ln = data[i]
                labels.append(data[i + 1:i + 1 + ln].decode("latin1"))
                i += 1 + ln
            if i >= len(data):
                continue
            qname = ".".join(labels)
            qtype = int.from_bytes(data[i + 1:i + 3], "big")
            question = data[12:i + 5]
            if qtype == 1:
                answer_ip = self.args.acs_ip if qname.lower() == "acs3.turk.net" else self.args.local_ip
                ans = (b"\xc0\x0c" + b"\x00\x01\x00\x01" + struct.pack("!I", 60) +
                       b"\x00\x04" + socket.inet_aton(answer_ip))
                flags = b"\x81\x80"
            else:
                ans = b""
                flags = b"\x81\x80"
            resp = tid + flags + b"\x00\x01" + (b"\x00\x01" if ans else b"\x00\x00") + b"\x00\x00\x00\x00"
            resp += question + ans
            try:
                s.sendto(resp, addr)
            except OSError:
                pass
            print("[dns] %s type=%d -> %s" % (qname, qtype, self.args.local_ip if ans else "no-answer"))
        s.close()

    def ntp_loop(self, stop):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            prepare_socket(s)
            s.bind((service_address(self.args.local_ip), 123))
        except OSError as e:
            print("[ntp] bind failed: %s" % e)
            return
        s.settimeout(0.5)
        print("[ntp] listening on %s:123" % service_address(self.args.local_ip))
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(64)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] != self.args.peer_ip:
                continue
            if len(data) < 48:
                continue
            now = time.time() + 2208988800
            sec = int(now)
            frac = int((now - int(now)) * (2 ** 32))
            ts = struct.pack("!II", sec, frac)
            resp = bytearray(48)
            resp[0] = 0x1c  # LI=0, VN=3, Mode=4 (server)
            resp[1] = 1     # stratum
            resp[2] = 6     # poll
            resp[3] = 0xfa  # precision
            resp[12:16] = b"LOCL"
            resp[16:24] = data[40:48]  # originate = client transmit
            resp[24:32] = ts
            resp[32:40] = ts
            try:
                s.sendto(bytes(resp), addr)
            except OSError:
                pass
            print("[ntp] reply to %s" % addr[0])
        s.close()

    def start_servers(self):
        if self.servers_started:
            return
        self.servers_started = True
        threading.Thread(target=self.dns_loop, args=(self.stop,), daemon=True).start()
        threading.Thread(target=self.ntp_loop, args=(self.stop,), daemon=True).start()

        # The diagnostic ACS only needs the configured ACS endpoints. Do not
        # impersonate the CPE's Connection Request listener or local APIs.
        for host in service_addresses(self.args.local_ip, self.args.acs_ip):
            port = 80
            try:
                srv = ACSServer((host, port), ACSState())
            except OSError as e:
                print("[acs] bind %d failed: %s" % (port, e))
                continue
            srv.allowed_peer = self.args.peer_ip
            self.owned_servers.append(srv)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            print("[acs] http listening on %s:%d" % (host, port))

        # HTTPS 443 with a throw-away cert (the CPE may enforce HTTPS).
        try:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", ACS_KEY_PATH, "-out", ACS_CERT_PATH, "-days", "2",
                 "-subj", "/CN=acs3.turk.net"],
                check=False, capture_output=True, timeout=20,
            )
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(ACS_CERT_PATH, ACS_KEY_PATH)
            for host in service_addresses(self.args.local_ip, self.args.acs_ip):
                srv = ACSServer((host, 443), ACSState())
                srv.tls_context = ctx
                srv.allowed_peer = self.args.peer_ip
                self.owned_servers.append(srv)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                print("[acs] https listening on %s:443" % host)
        except Exception as e:
            print("[acs] https 443 failed: %s" % e)

    def tap_loop(self, iface, stop):
        while not stop.is_set():
            try:
                p = subprocess.Popen(
                    ["tcpdump", "-i", iface, "-n", "-l", "-c", "300"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
            except Exception as e:
                print("[tap] tcpdump failed: %s" % e)
                return
            self.owned_captures.append(p)
            print("[tap] tcpdump on %s (tcp + ntp)" % iface)
            for line in p.stdout:
                if stop.is_set():
                    p.terminate()
                    return
                print("[tap] " + line.decode("utf-8", "replace").rstrip())
            p.terminate()
            time.sleep(0.5)

    def add_acs_alias(self, iface):
        ip = self.args.acs_ip
        if not ip or ip == self.args.local_ip:
            return True
        added = add_acs_alias(iface, ip)
        print("[ppp] %s alias %s %s" % (iface, ip, "added" if added else "failed; will retry"))
        return added

    def monitor_ppp(self):
        while not self.stop.is_set():
            iface = find_ppp_interface(self.args.local_ip, self.args.peer_ip, self.ppp_name)
            if not iface:
                self.acs_alias_iface = None
            if iface and getattr(self, "acs_alias_iface", None) != iface:
                if self.add_acs_alias(iface):
                    self.acs_alias_iface = iface
            if iface and (not getattr(self, "tap_started", False) or iface != getattr(self, "tap_iface", None)):
                self.tap_started = True
                self.tap_iface = iface
                threading.Thread(target=self.tap_loop, args=(iface, self.stop), daemon=True).start()
            self.stop.wait(0.3)

    def hard_stop(self):
        print("[*] max runtime reached, exiting")
        self.stop.set()
        try:
            self.stop_pppd()
        except Exception:
            pass
        os._exit(0)

    def cleanup_stale(self):
        # Never kill unrelated pppd processes or bring down arbitrary pppN
        # interfaces; this run owns only the child stored in self.pppd.
        print("[*] leaving existing PPP processes/interfaces untouched")

    def run(self):
        self.cleanup_stale()
        threading.Timer(self.args.max_runtime, self.hard_stop).start()
        print("[*] " + firewall_status())
        self.start_servers()
        print("[*] PPPoE server on %s vlan %d, mac %s, peer %s"
              % (self.iface, self.vlan, self.our_mac, self.peer_mac))
        self.tx_sock = conf.L2socket(iface=self.iface)
        threading.Thread(target=self.tx_loop, daemon=True).start()
        threading.Thread(target=self.monitor_ppp, daemon=True).start()
        if getattr(self.args, 'mode', 'write') == 'configure':
            print("[*] SELECTED CONFIGURATION: verify CLI account, apply selected fields, read back values")
        else:
            print("[*] BOUNDED WRITE TEST: engineer RebootPersistent 1 -> 0 -> 1 with readback")
        print("[*] waiting for PADI; pppd starts on PADR; Ctrl-C to stop")
        print("[*] Vantiva açık olmalı; WAN kablosu tanılama bilgisayarına bağlı olmalı.")
        print("[*] Otomatik PPPoE denemesini bekleyin; yalnızca PADI gelmezse WAN bağlantısını yeniden tetikleyin.")
        try:
            capture_session(self, AsyncSniffer)
        except KeyboardInterrupt:
            pass
        self.stop.set()
        self.stop_pppd()
        try:
            self.tx_sock.close()
        except Exception:
            pass
        print("[*] done")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="en11")
    ap.add_argument("--vlan", type=int, default=35)
    ap.add_argument("--peer-mac", default="60:d8:a4:97:16:d9")
    ap.add_argument("--local-ip", default="10.116.13.100")
    ap.add_argument("--acs-ip", default="193.192.97.234")
    ap.add_argument("--peer-ip", default="10.116.13.101")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--max-runtime", type=int, default=330)
    ap.add_argument("--no-pppd", action="store_true")
    args = ap.parse_args()
    log_fd = os.open(LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(log_fd, 0o600)
    logf = os.fdopen(log_fd, "a", buffering=1)
    sys.stdout = Tee(getattr(sys, "__stdout__", sys.stdout), logf)
    sys.stderr = Tee(getattr(sys, "__stderr__", sys.stderr), logf)
    print("[*] log file: %s" % LOG_PATH)
    Bridge(args).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
