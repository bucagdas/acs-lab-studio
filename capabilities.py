"""Read-only CWMP method and metadata inventory. Never sends a write/transfer RPC."""
import json
import re


def install(engine, run):
    groups = [
        ('web_users', 'Device.Users.User.', r'Device\.Users\.User\.[1-9]\d*\.(?:Username|X_000E50_Role)'),
        ('vendor_logs', 'Device.DeviceInfo.VendorLogFile.', r'Device\.DeviceInfo\.VendorLogFile\.[1-9]\d*\.(?:Name|Persistent|MaximumSize)'),
        ('cli_users', 'Device.Services.X_000E50_AccessManagement.SSH.CliUsers.', r'Device\.Services\.X_000E50_AccessManagement\.SSH\.CliUsers\.[1-9]\d*\.(?:Username|Enable|Access|RebootPersistent)'),
        ('log_settings', 'uci.system.system.', r'uci\.system\.system\.[^.]+\.(?:log_file|log_filter_file)'),
        ('dropbear_lan', 'uci.dropbear.dropbear.@lan.', r'uci\.dropbear\.dropbear\.@lan\.(?:enable|Interface|Port|RootLogin|RootPasswordAuth|PasswordAuth)'),
    ]
    report = {'status': 'pending', 'methods': [], 'groups': {}}
    destination = run / 'capabilities.json'

    def save():
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2))

    class InventoryHandler(engine.ACSHandler):
        def _inventory_request(self, stage, build):
            st = self.server.state
            mid = st.next_id()
            st.pending_id = mid
            st.stage = stage
            self._send(200, build(mid))

        def _inventory_matches(self, received_id):
            if received_id == self.server.state.pending_id:
                return True
            report['status'] = 'failed'
            report['error'] = 'RPC response ID mismatch'
            save()
            self.server.state.stage = 'inventory_failed'
            print('[acs] Inventory failed: response ID mismatch; no further RPC sent', flush=True)
            self._send(204)
            return False

        def _inventory_next(self):
            st = self.server.state
            st.inventory_index += 1
            if st.inventory_index >= len(groups):
                report['status'] = 'complete'
                save()
                st.stage = 'complete_read_only'
                print('[acs] read-only diagnostic complete; methods and metadata saved; no write or transfer requested', flush=True)
                self._send(204)
                return
            group, path, _ = groups[st.inventory_index]
            report['groups'][group] = {'path': path, 'status': 'pending', 'parameters': {}}
            save()
            self._inventory_request('inventory_names', lambda mid: engine._get_parameter_names(st.namespace, mid, path))

        def _handle_rpc_methods_response(self, root, received_id):
            if not self._inventory_matches(received_id):
                return
            methods = sorted(set(n.text or '' for n in root.iter() if engine._local_name(n.tag) == 'string'))
            report['methods'] = methods
            report['status'] = 'running'
            save()
            print('[acs] CPE RPC methods: ' + ', '.join(methods), flush=True)
            print('[acs] Download=%s Upload=%s (advertised support only; transfers not attempted)' % ('yes' if 'Download' in methods else 'no', 'yes' if 'Upload' in methods else 'no'), flush=True)
            if not {'GetParameterNames', 'GetParameterValues'}.issubset(methods):
                report['status'] = 'unsupported'
                save()
                self.server.state.stage = 'inventory_unsupported'
                self._send(204)
                return
            self.server.state.inventory_index = -1
            self._inventory_next()

        def _handle_get_names_response(self, root, received_id):
            if not self._inventory_matches(received_id):
                return
            st = self.server.state
            group, _, pattern = groups[st.inventory_index]
            entry = report['groups'][group]
            paths = []
            for node in root.iter():
                if engine._local_name(node.tag) != 'ParameterInfoStruct':
                    continue
                name = next((c.text or '' for c in node if engine._local_name(c.tag) == 'Name'), '')
                writable = next((c.text or '' for c in node if engine._local_name(c.tag) == 'Writable'), '')
                if re.fullmatch(pattern, name) and name not in entry['parameters']:
                    paths.append(name)
                    entry['parameters'][name] = {'writable': writable in ('1', 'true')}
            if len(paths) > 128:
                entry['status'] = 'limit_exceeded'
                entry['parameters'] = {}
                save()
                self._inventory_next()
                return
            if not paths:
                entry['status'] = 'no_matching_parameters'
                save()
                self._inventory_next()
                return
            st.inventory_paths = paths
            self._inventory_request('inventory_values', lambda mid: engine._get_parameter_values(st.namespace, mid, paths))

        def _handle_get_values_response(self, root, received_id):
            if not self._inventory_matches(received_id):
                return
            st = self.server.state
            group = groups[st.inventory_index][0]
            entry = report['groups'][group]
            for node in root.iter():
                if engine._local_name(node.tag) != 'ParameterValueStruct':
                    continue
                name = next((c.text or '' for c in node if engine._local_name(c.tag) == 'Name'), '')
                value = next((c.text or '' for c in node if engine._local_name(c.tag) == 'Value'), '')
                if name in st.inventory_paths:
                    entry['parameters'][name]['value'] = value
                    print('[acs] current value %s = %r' % (name, value), flush=True)
            entry['status'] = 'read' if all('value' in x for x in entry['parameters'].values()) else 'incomplete'
            save()
            self._inventory_next()

        def _handle_profile_fault(self, root, received_id):
            if not self._inventory_matches(received_id):
                return
            st = self.server.state
            if not hasattr(st, 'inventory_index') or st.inventory_index < 0:
                report['status'] = 'failed'
                save()
                self._send(204)
                return
            group = groups[st.inventory_index][0]
            code = engine._find_text(root, 'FaultCode')
            report['groups'][group].update(status='fault', fault_code=code)
            print('[acs] Inventory group %s: SOAP Fault %s; continuing read-only queries' % (group, code), flush=True)
            save()
            self._inventory_next()

    engine.ACSHandler = InventoryHandler
