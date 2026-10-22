import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('retention', Path(__file__).parents[1] / 'scripts/retention.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def csv(ids):
    return base64.b64encode(('id\n' + ''.join(str(i) + '\n' for i in ids)).encode()).decode()


class Fake:
    def __init__(self):
        self.ids = {101: [], 202: []}
        self.active = 'N'
        self.calls = []
        self.fail = False

    def __call__(self, method, *args):
        self.calls.append((method, args))
        if method == 'get_survey_properties':
            return {'active': self.active, 'anonymized': 'Y', 'datestamp': 'N'}
        if method == 'get_summary':
            return str(len(self.ids[args[0]]))
        if method == 'export_responses':
            if not self.ids[args[0]]:
                if self.active == 'N':
                    return {'status': 'No Data, survey table does not exist.',
                            'error_code': 'ERR_NO_RESPONSE_TABLE'}
                return {'status': 'No Data, could not get max id.', 'error_code': 'ERR_NO_DATA'}
            return csv(self.ids[args[0]])
        if method == 'delete_response':
            if self.fail:
                self.fail = False
                raise r.RetentionError('rpc_failed')
            sid, rid = args
            if rid not in self.ids[sid]:
                return {'status': 'Response Id not found', 'error_code': 'ERR_NOT_FOUND'}
            self.ids[sid].remove(rid)
            return {str(rid): 'deleted'}
        raise AssertionError(method)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'ledger.json'
        self.config = {'surveys': [{'id': 101, 'language': 'ro'}, {'id': 202, 'language': 'en'}]}
        self.api = Fake()
        self.now = 100000

    def run_job(self, **kw):
        return r.run(self.config, self.state, self.api, self.now, **kw)

    def init(self):
        self.run_job(initialize=True, apply=True)

    def test_strict_export(self):
        self.assertEqual(r.parse_ids(csv([1, 2])), {'1', '2'})
        for data in ['***', base64.b64encode(b'id,answer\n1,secret\n').decode(),
                     csv([1, 1]), csv(['01']), csv(['x']),
                     base64.b64encode(b'id\n""\n').decode(),
                     base64.b64encode(b'ID\n1\n').decode()]:
            with self.subTest(data=data), self.assertRaises(r.RetentionError):
                r.parse_ids(data)

    def test_export_allows_one_trailing_empty_record_only(self):
        for raw, expected in ((b'"id"\r\n"7"\r\n\r\n', {'7'}),
                              (b'id\n7\n\n', {'7'}),
                              (b'id\r\n\r\n', set())):
            with self.subTest(raw=raw):
                self.assertEqual(r.parse_ids(base64.b64encode(raw).decode()), expected)
        for raw in (b'id\n\n7\n', b'id\n7\n\n8\n',
                    b'id\n7\n\n\n', b'id\n\n\n',
                    b'id\n7\n""\n', b'id\n7\n \n',
                    b'id\n7\n,\n', b'\nid\n7\n'):
            with self.subTest(raw=raw), self.assertRaises(r.RetentionError):
                r.parse_ids(base64.b64encode(raw).decode())

    def test_initialization_requires_two_inactive_empty_surveys(self):
        self.config['surveys'].pop()
        with self.assertRaises(r.RetentionError): self.run_job(initialize=True, apply=True)
        self.config['surveys'].append({'id': 202, 'language': 'en'})
        self.api.active = 'Y'
        with self.assertRaises(r.RetentionError): self.init()
        self.api.active = 'N'
        self.api.ids[202] = [1]
        with self.assertRaises(r.RetentionError): self.init()
        self.assertFalse(self.state.exists())

    def test_missing_corrupt_and_public_state_fail(self):
        with self.assertRaises(r.RetentionError): self.run_job()
        self.state.write_text('garbage')
        self.state.chmod(0o600)
        with self.assertRaises(r.RetentionError): self.run_job()
        self.init_state_after_remove()
        self.state.chmod(0o644)
        with self.assertRaises(r.RetentionError): self.run_job()

    def init_state_after_remove(self):
        self.state.unlink()
        self.init()

    def test_new_cohort_uses_prior_scan_and_explicit_id_export(self):
        self.init()
        self.api.active = 'Y'
        self.api.ids[101] = [7]
        self.now += 300
        self.run_job(apply=True)
        state = json.loads(self.state.read_text())
        self.assertEqual(state['surveys']['101']['ids']['7'], 100000)
        exports = [args for method, args in self.api.calls if method == 'export_responses']
        self.assertEqual(exports[0], (101, 'csv', 'ro', 'all', 'code', 'short', None, None, ['id']))

    def test_dry_run_does_not_write_or_delete(self):
        self.init()
        before = self.state.read_bytes()
        self.api.ids[101] = [7]
        self.now += 300
        self.run_job()
        self.assertEqual(before, self.state.read_bytes())
        self.assertFalse(any(m == 'delete_response' for m, _ in self.api.calls))

    def mature(self):
        self.init()
        self.api.active = 'Y'
        self.api.ids[101] = [7, 8]
        self.now += 300
        self.run_job(apply=True)
        data = json.loads(self.state.read_text())
        self.now = 100000 + r.RETENTION - r.MARGIN
        data['last_scan'] = self.now - 300
        self.state.write_text(json.dumps(data))

    def test_no_early_deletion_then_due_deletion(self):
        self.mature()
        self.now -= 1
        self.run_job(apply=True)
        self.assertEqual(self.api.ids[101], [7, 8])
        self.now += 1
        self.run_job(apply=True)
        self.assertEqual(self.api.ids[101], [])

    def test_partial_failure_preserves_retry_state(self):
        self.mature()
        self.api.fail = True
        with self.assertRaises(r.RetentionError): self.run_job(apply=True)
        self.assertEqual(set(json.loads(self.state.read_text())['surveys']['101']['ids']), {'7', '8'})
        self.run_job(apply=True)
        self.assertEqual(self.api.ids[101], [])

    def test_missing_response_is_idempotent(self):
        self.assertTrue(r.deleted({'status': 'Response Id not found', 'error_code': 'ERR_NOT_FOUND'}, '7'))
        self.assertTrue(r.deleted({'7': 'deleted'}, '7'))
        self.assertFalse(r.deleted({'error_code': 'ERR_NOT_FOUND'}, '7'))
        self.assertFalse(r.deleted({'status': 'wrong', 'error_code': 'ERR_NOT_FOUND'}, '7'))
        self.assertFalse(r.deleted({'8': 'deleted'}, '7'))
        self.assertFalse(r.deleted({'7': 'deleted', '8': 'deleted'}, '7'))
        self.assertFalse(r.deleted([7], '7'))
        self.assertFalse(r.deleted({'status': 'secret password'}, '7'))
        self.assertFalse(r.deleted([8], '7'))

    def test_unknown_survey_state_stale_scan_and_backward_clock_fail(self):
        self.init()
        self.config['surveys'][1]['id'] = 303
        with self.assertRaises(r.RetentionError): self.run_job(apply=True)
        self.config['surveys'][1]['id'] = 202
        self.now += r.MAX_GAP + 1
        with self.assertRaises(r.RetentionError): self.run_job(apply=True)
        self.now = 99999
        with self.assertRaises(r.RetentionError): self.run_job(apply=True)

    def test_second_export_invalid_prevents_any_deletion(self):
        self.mature()
        original = self.api
        def invalid_second(method, *args):
            if method == 'export_responses' and args[0] == 202:
                return base64.b64encode(b'id,answer\n1,private\n').decode()
            return original(method, *args)
        with self.assertRaises(r.RetentionError):
            r.run(self.config, self.state, invalid_second, self.now, apply=True)
        self.assertEqual(self.api.ids[101], [7, 8])
        self.assertFalse(any(m == 'delete_response' for m, _ in self.api.calls))

    def test_failure_after_one_delete_checkpoints_and_retries(self):
        self.mature()
        original = self.api
        deletes = []
        def partial(method, *args):
            if method == 'delete_response':
                deletes.append(args)
                if len(deletes) == 2:
                    raise r.RetentionError('rpc_failed')
            return original(method, *args)
        with self.assertRaises(r.RetentionError):
            r.run(self.config, self.state, partial, self.now, apply=True)
        self.assertEqual(len(self.api.ids[101]), 1)
        ledger = json.loads(self.state.read_text())
        self.assertEqual(len(ledger['surveys']['101']['ids']), 1)
        self.assertEqual(ledger['last_scan'], self.now - 300)
        self.run_job(apply=True)
        self.assertEqual(self.api.ids[101], [])

    def test_exact_inactive_no_data_initialization(self):
        original = self.api
        def no_data(method, *args):
            if method == 'get_summary':
                return {'status': 'No available data', 'error_code': 'ERR_NO_DATA'}
            if method == 'export_responses':
                return {'status': 'No Data, survey table does not exist.', 'error_code': 'ERR_NO_RESPONSE_TABLE'}
            return original(method, *args)
        r.run(self.config, self.state, no_data, self.now, initialize=True, apply=True)
        r.run(self.config, self.state, no_data, self.now + 300, apply=True)
        self.api.active = 'Y'
        with self.assertRaises(r.RetentionError):
            r.run(self.config, self.state, no_data, self.now + 600, apply=True)

    def test_after_last_deletion_empty_active_table_scans_successfully(self):
        self.mature()
        self.run_job(apply=True)
        self.now += 300
        self.run_job(apply=True)
        ledger = json.loads(self.state.read_text())
        self.assertEqual(ledger['last_scan'], self.now)
        self.assertEqual(ledger['surveys']['101']['ids'], {})

    def test_empty_active_export_reconciles_interrupted_last_deletion(self):
        self.mature()
        self.api.ids[101] = []  # Remote deletion completed before ledger save.
        self.run_job(apply=True)
        self.assertEqual(json.loads(self.state.read_text())['surveys']['101']['ids'], {})

    def test_empty_error_pairs_and_state_conditions_are_strict(self):
        self.mature()
        original = self.api
        invalid = [
            {'status': 'No available data', 'error_code': 'ERR_NO_DATA'},
            {'status': 'No Data, could not get max id.', 'error_code': 'ERR_NO_RESPONSE_TABLE'},
            {'status': 'No Data, survey table does not exist.', 'error_code': 'ERR_NO_DATA'},
            {'status': 'No Data, survey table does not exist.', 'error_code': 'ERR_NO_RESPONSE_TABLE'},
            {'status': 'No Data, could not get max id.', 'error_code': 'ERR_NO_DATA', 'extra': 1},
        ]
        for response in invalid:
            def bad(method, *args):
                if method == 'export_responses' and args[0] == 101:
                    return response
                return original(method, *args)
            with self.subTest(response=response), self.assertRaises(r.RetentionError):
                r.run(self.config, self.state, bad, self.now, apply=True)
        self.api.active = 'N'
        for response in (
            {'status': 'No Data, survey table does not exist.', 'error_code': 'ERR_NO_RESPONSE_TABLE'},
            {'status': 'No Data, could not get max id.', 'error_code': 'ERR_NO_DATA'},
        ):
            with self.subTest(inactive=response), self.assertRaises(r.RetentionError):
                r.run(self.config, self.state, bad, self.now, apply=True)
        self.assertFalse(any(m == 'delete_response' for m, _ in self.api.calls))

    def test_rpc_rejects_public_or_named_endpoints_before_network(self):
        for endpoint in ('https://127.0.0.1/rpc', 'http://localhost/rpc',
                         'http://192.0.2.1/rpc', 'http://user:secret@127.0.0.1/rpc',
                         'http://127.0.0.1/rpc?token=secret',
                         'http://127.0.0.1/index.php?r=admin/remotecontrol&token=secret',
                         'http://127.0.0.1/index.php?r=admin%2Fremotecontrol',
                         'http://127.0.0.1/index.php?r=admin/remotecontrol&r=other',
                         'http://127.0.0.1/index.php?r=admin/remotecontrol#fragment'):
            with self.subTest(endpoint=endpoint), self.assertRaises((r.RetentionError, ValueError)):
                r.RPC({'endpoint': endpoint, 'username': 'test', 'password': 'secret'})

    def test_rpc_accepts_only_exact_installed_routing_query_or_no_query(self):
        from unittest.mock import patch
        for endpoint in ('http://127.0.0.1:18080/index.php?r=admin/remotecontrol',
                         'http://127.0.0.1:18080/index.php/admin/remotecontrol',
                         'http://[::1]:18080/index.php?r=admin/remotecontrol'):
            with self.subTest(endpoint=endpoint), patch.object(r.RPC, 'request', return_value='synthetic-session-key') as request:
                api = r.RPC({'endpoint': endpoint, 'username': 'test', 'password': 'secret'})
                self.assertEqual(api.url, endpoint)
                request.assert_called_once_with('get_session_key', ['test', 'secret'])

    def test_safe_error_output(self):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            code = r.main(['--config', str(Path(self.tmp.name) / 'secret-token-missing')])
        self.assertEqual(code, 1)
        self.assertNotIn('secret-token', out.getvalue())
        self.assertNotIn('Traceback', out.getvalue())


if __name__ == '__main__':
    unittest.main()
