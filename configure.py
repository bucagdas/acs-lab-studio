"""Allowlisted web-admin role and SSH account settings over CWMP."""
import html
import json
import os
import re


def install(engine, settings, run):
    target = settings['target']
    base = f'Device.Services.X_000E50_AccessManagement.SSH.CliUsers.{target}.'
    expected_user = {1: 'engineer', 2: 'superuser'}[target]
    fields = {}
    if settings['ssh_action'] == 'enable':
        fields.update(Access=('LAN', 'string'), Enable=('1', 'boolean'))
    elif settings['ssh_action'] == 'disable':
        fields.update(Access=('NONE', 'string'), Enable=('0', 'boolean'))
    if settings['persistence'] != 'keep':
        fields['RebootPersistent'] = (settings['persistence'], 'boolean')
    password = settings.get('cli_password', '')
    if password:
        fields['Password'] = (password, 'string')
    desired_role = settings.get('web_admin_role', 'keep')
    web_requested = desired_role in ('engineer', 'admin')
    readable = ['Username', 'Enable', 'Access', 'RebootPersistent'] if fields else []
    original_trace = engine._trace_cwmp

    def trace(direction, peer, summary, body=b''):
        if password and body:
            body = body.replace(password.encode(), b'[REDACTED]')
        return original_trace(direction, peer, summary, body)
    engine._trace_cwmp = trace
    journal = run / 'configuration-state.json'

    class ConfiguredHandler(engine.ACSHandler):
        def _save(self, status, **extras):
            st = self.server.state
            state = {'status': status, 'target': target if fields else None,
                     'username': expected_user if fields else None,
                     'desired': {name: value for name, (value, _) in fields.items() if name != 'Password'},
                     'passwordRequested': bool(password),
                     'webAdmin': getattr(st, 'config_web', None), **extras}
            with journal.open('w') as f:
                json.dump(state, f)
                f.flush()
                os.fsync(f.fileno())

        def _config_fail(self, message):
            print('[config] CONFIG_FAILED: ' + message, flush=True)
            self._save('unverified', reason=message,
                       original=getattr(self.server.state, 'config_original', {}))
            self.server.state.stage = 'config_failed'
            self._send(204)

        def _config_request(self, stage, body_builder):
            st = self.server.state
            msg_id = st.next_id()
            st.pending_id = msg_id
            st.stage = stage
            self._send(200, body_builder(msg_id))

        def _config_matches(self, received_id):
            if received_id != self.server.state.pending_id:
                self._config_fail('RPC yanıt kimliği eşleşmedi.')
                return False
            return True

        def _read_paths(self):
            paths = [base + x for x in readable]
            web = getattr(self.server.state, 'config_web', None)
            if web:
                paths += [web['path'] + 'Username', web['path'] + 'X_000E50_Role']
            return paths

        def _next_baseline(self):
            if fields:
                self._config_request('config_names', lambda mid: engine._get_parameter_names(self.server.state.namespace, mid, base))
            else:
                self.server.state.config_original = {}
                self._send_selected()

        def _handle_rpc_methods_response(self, root, received_id):
            if not self._config_matches(received_id):
                return
            methods = [node.text for node in root.iter() if engine._local_name(node.tag) == 'string']
            if not {'GetParameterNames', 'GetParameterValues', 'SetParameterValues'}.issubset(methods):
                self._config_fail('Gerekli ACS yöntemleri cihaz tarafından bildirilmedi.')
                return
            if web_requested:
                print('[config] Web admin kaydı ve yazılabilir rol alanı aranıyor', flush=True)
                self._config_request('web_names', lambda mid: engine._get_parameter_names(self.server.state.namespace, mid, 'Device.Users.User.'))
            else:
                self._next_baseline()

        def _handle_get_names_response(self, root, received_id):
            if not self._config_matches(received_id):
                return
            writable = {}
            for node in root.iter():
                if engine._local_name(node.tag) != 'ParameterInfoStruct':
                    continue
                name = next((c.text for c in node if engine._local_name(c.tag) == 'Name'), '')
                flag = next((c.text for c in node if engine._local_name(c.tag) == 'Writable'), '')
                if name in writable:
                    self._config_fail('Yinelenen parametre bilgisi alındı.')
                    return
                writable[name] = flag in ('1', 'true')
            st = self.server.state
            if st.stage == 'web_names':
                usernames = sorted(name for name in writable if re.fullmatch(r'Device\.Users\.User\.[1-9]\d*\.Username', name))
                if not usernames or len(usernames) > 128:
                    self._config_fail('Web kullanıcı listesi alınamadı veya beklenen sınırı aşıyor.')
                    return
                st.web_writable = writable
                st.web_usernames = usernames
                paths = list(usernames)
                paths += [username.rsplit('.', 1)[0] + '.X_000E50_Role' for username in usernames if username.rsplit('.', 1)[0] + '.X_000E50_Role' in writable]
                self._config_request('web_identity', lambda mid: engine._get_parameter_values(st.namespace, mid, paths))
                return
            if st.stage != 'config_names' or not all(writable.get(base + name) for name in fields):
                self._config_fail('Seçilen SSH alanlarından en az biri ACS üzerinden yazılabilir değil.')
                return
            print('[config] Selected fields writable; reading target account before changes', flush=True)
            self._config_request('config_baseline', lambda mid: engine._get_parameter_values(st.namespace, mid, [base + x for x in readable]))

        def _handle_get_values_response(self, root, received_id):
            if not self._config_matches(received_id):
                return
            st = self.server.state
            values = {}
            for node in root.iter():
                if engine._local_name(node.tag) != 'ParameterValueStruct':
                    continue
                name = next((c.text or '' for c in node if engine._local_name(c.tag) == 'Name'), '')
                value = next((c.text or '' for c in node if engine._local_name(c.tag) == 'Value'), '')
                if name in values:
                    self._config_fail('Yinelenen parametre değeri alındı.')
                    return
                values[name] = value
            if st.stage == 'web_identity':
                if any(path not in values for path in st.web_usernames):
                    self._config_fail('Web kullanıcı adları eksik döndü; admin güvenle seçilemedi.')
                    return
                matches = [path for path in st.web_usernames if values[path] == 'admin']
                if len(matches) != 1:
                    self._config_fail('Tek bir admin web kullanıcısı doğrulanamadı; yazma yapılmadı.')
                    return
                web_base = matches[0].rsplit('.', 1)[0] + '.'
                role_path = web_base + 'X_000E50_Role'
                if not st.web_writable.get(role_path) or not values.get(role_path):
                    self._config_fail('admin rol alanı yazılabilir değil veya mevcut rol okunamadı.')
                    return
                st.config_web = {'path': web_base, 'username': 'admin',
                                 'originalRole': values[role_path], 'desiredRole': desired_role}
                print('[config] Web admin bulundu: %s; mevcut rol=%s; hedef rol=%s' % (web_base, values[role_path], desired_role), flush=True)
                self._next_baseline()
                return
            cli = {}
            for field in readable:
                if base + field in values:
                    value = values[base + field]
                    cli[field] = {'true': '1', 'false': '0'}.get(value, value)
                    print('[acs] current value %s = %r' % (base + field, value), flush=True)
            if st.stage == 'config_baseline':
                if set(cli) != set(readable) or cli.get('Username') != expected_user:
                    self._config_fail('Hedef SSH hesabı veya başlangıç verileri doğrulanamadı.')
                    return
                st.config_original = cli
                self._send_selected()
            elif st.stage == 'config_verify':
                desired = {name: value for name, (value, _) in fields.items() if name != 'Password'}
                cli_ok = not fields or (cli.get('Username') == expected_user and all(cli.get(name) == value for name, value in desired.items()))
                web = getattr(st, 'config_web', None)
                web_ok = not web or (values.get(web['path'] + 'Username') == 'admin' and values.get(web['path'] + 'X_000E50_Role') == desired_role)
                if not cli_ok or not web_ok:
                    self._config_fail('Yazılan ayarların okuma sonucu eşleşmedi; yeniden yazma yapılmadı.')
                    return
                if web:
                    web['verifiedRole'] = desired_role
                    print('[config] Web admin rolü tekrar okundu: ' + desired_role, flush=True)
                status = 'password_acknowledged' if password else 'verified'
                self._save(status, original=st.config_original, readback=cli, rpcStatus=st.config_status)
                if password:
                    print('[config] CONFIG_PASSWORD_ACKNOWLEDGED: other selected fields verified; verify the CLI password with an SSH login', flush=True)
                else:
                    print('[config] CONFIG_APPLIED_VERIFIED', flush=True)
                st.stage = 'config_done'
                self._send(204)
            else:
                self._config_fail('Beklenmeyen yapılandırma aşaması.')

        def _send_selected(self):
            st = self.server.state
            params = {base + name: value for name, value in fields.items()}
            web = getattr(st, 'config_web', None)
            if web:
                params[web['path'] + 'X_000E50_Role'] = (desired_role, 'string')
            if not params:
                self._config_fail('Yazılacak ayar seçilmedi.')
                return
            self._save('pending', original=st.config_original)
            def body(mid):
                items = ['<ParameterValueStruct><Name>' + name + '</Name><Value xsi:type="xsd:' + kind + '">' + html.escape(value, quote=True) + '</Value></ParameterValueStruct>' for name, (value, kind) in params.items()]
                inner = ('<cwmp:SetParameterValues><ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[' + str(len(items)) + ']">' + ''.join(items) + '</ParameterList><ParameterKey></ParameterKey></cwmp:SetParameterValues>')
                return engine._envelope(st.namespace, inner, mid)
            print('[config] Sending selected settings; web admin=%s; SSH hesabı=%s' % (desired_role + ' rolü' if web else 'değişmez', expected_user if fields else 'değişmez'), flush=True)
            self._config_request('config_set', body)

        def _handle_set_response(self, root, received_id):
            if not self._config_matches(received_id):
                return
            st = self.server.state
            status = engine._find_text(root, 'Status')
            if st.stage != 'config_set' or status not in ('0', '1'):
                self._config_fail('Yazma RPC sonucu geçersiz.')
                return
            st.config_status = status
            self._save('acknowledged', original=st.config_original, rpcStatus=status)
            print('[config] SetParameterValuesResponse status=' + status + '; reading back selected settings', flush=True)
            self._config_request('config_verify', lambda mid: engine._get_parameter_values(st.namespace, mid, self._read_paths()))

        def _handle_profile_fault(self, root, received_id):
            if self._config_matches(received_id):
                self._config_fail('Cihaz SOAP Fault bildirdi. Kod: ' + str(engine._find_text(root, 'FaultCode')))

    engine.ACSHandler = ConfiguredHandler
