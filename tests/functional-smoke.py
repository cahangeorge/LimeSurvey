#!/usr/bin/env python3
"""Synthetic disposable public roundtrip. Never print raw runtime failures."""
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import zipfile

UPSTREAM = '6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9'
CHROME_VERSION = '155.0.8059.39'
CHROME_SHA256 = 'b9d44e5d183260ca941a4c4d8d21c8a437d81ef778a489047ef98968b0475dc5'
REQUIREMENTS = '''playwright==1.63.0 --hash=sha256:354e15b29503565fc598b89f16fbe070459343bef9d7498a93e304864000c6a7
greenlet==3.5.6 --hash=sha256:e85880b538e59a59f55117b81f208a6660ad5ac328aad9305f812d9b8bc67a0f
pyee==13.0.1 --hash=sha256:af2f8fede4171ef667dfded53f96e2ed0d6e6bd7ee3bb46437f77e3b57689228
typing_extensions==4.16.0 --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8
'''
ROOT = Path(__file__).resolve().parents[1]


class GateError(Exception):
    pass


def require(condition):
    if not condition:
        raise GateError('gate requirement failed')


def run(args, *, data=None, timeout=180, env=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, env=env)
    require(result.returncode == 0)
    return result.stdout


def rpc_result(body):
    require(isinstance(body, dict) and body.get('id') == 1)
    require(not body.get('error') and 'result' in body)
    result = body['result']
    require(result is not None and not (isinstance(result, dict) and
            (result.get('status') not in (None, 'OK') or 'error_code' in result or 'errors' in result)))
    return result


def exported(encoded, marker):
    require(isinstance(encoded, str))
    raw = base64.b64decode(encoded, validate=True).decode('utf-8-sig')
    reader = csv.DictReader(io.StringIO(raw), delimiter=';')
    fields = reader.fieldnames or []
    require(len(fields) == len(set(fields)))
    require({'id', 'submitdate', 'SMOKE'} <= set(fields))
    rows = list(reader)
    require(len(rows) == 1)
    row = rows[0]
    require(row['SMOKE'] == marker and bool(row['submitdate'].strip()))
    require(bool(re.fullmatch(r'[1-9][0-9]*', row['id'])))
    return row['id'], hashlib.sha256(raw.encode()).hexdigest()


def safe_project(project):
    require(bool(re.fullmatch(r'ls-functional-[0-9a-f]{32}', project)))


def clean_environment():
    for key in ('COMPOSE_PROJECT_NAME', 'COMPOSE_FILE', 'COMPOSE_PROFILES',
                'ENV_FILE', 'KEEP_SMOKE_STACK', 'DOCKER_HOST', 'DOCKER_CONTEXT'):
        require(not os.environ.get(key))
    require(not any(k.startswith('COMPOSE_') and v for k, v in os.environ.items()))
    return {k: v for k, v in os.environ.items()
            if not k.startswith(('COMPOSE_', 'DB_', 'RESEND_'))}


def validate_config(config, project):
    safe_project(project)
    require(config['name'] == project and set(config['services']) == {'db', 'app', 'nginx'})
    volumes = config['volumes']
    require(len(volumes) == 7)
    for spec in volumes.values():
        require(not spec.get('external') and not spec.get('driver_opts') and
                spec['name'].startswith(project + '_'))
    for spec in config['networks'].values():
        require(not spec.get('external') and not spec.get('driver_opts') and
                spec['name'].startswith(project + '_'))
    require(config['networks'].get('backend', {}).get('internal') is True)
    require(set(config['services']['db'].get('networks', {})) == {'backend'})
    for name, service in config['services'].items():
        require(not service.get('network_mode'))
        require(not service.get('container_name'))
        require(service['environment'].get('DB_HOST', 'db') == 'db')
        for port in service.get('ports', []):
            require(name == 'nginx' and port['host_ip'] == '127.0.0.1' and
                    int(port['target']) == 80 and str(port['published']) == '0')
        for mount in service.get('volumes', []):
            require(mount['type'] == 'volume' and mount['source'] in volumes or
                    name == 'nginx' and mount['type'] == 'bind' and
                    mount['source'] == str(ROOT / 'docker/nginx/default.conf') and
                    mount.get('read_only') is True)
    require(len(config['services']['nginx'].get('ports', [])) == 1)


def browser_options(executable):
    chrome = Path(executable).resolve()
    require(os.geteuid() != 0 and chrome.is_file())
    local = Path('/home/gion/.cache/chrome-for-testing/stable/chrome-linux64/chrome')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted')
        expected = Path(os.environ['RUNNER_TEMP']).resolve() / 'functional-tools/chrome-linux-arm64/chrome'
    else:
        expected = local.resolve()
    require(chrome == expected)
    version = run([str(chrome), '--version']).decode().strip()
    require(bool(re.fullmatch(r'Google Chrome for Testing [0-9.]+', version)))
    return {'executable_path': str(chrome), 'headless': True, 'chromium_sandbox': True}, version


def bootstrap(directory):
    require(platform.machine() == 'aarch64' and sys.version_info[:2] == (3, 12))
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted')
    dest = Path(directory).resolve()
    require(dest == Path(os.environ['RUNNER_TEMP']).resolve() / 'functional-tools')
    require(not dest.exists())
    dest.mkdir(mode=0o700)
    run([sys.executable, '-m', 'venv', str(dest / 'venv')])
    python = str(dest / 'venv/bin/python')
    run([python, '-m', 'pip', 'install', '--disable-pip-version-check',
         '--require-hashes', '--only-binary=:all:', '-r', '/dev/stdin'],
        data=REQUIREMENTS.encode(), timeout=240)
    url = (f'https://storage.googleapis.com/chrome-for-testing-public/{CHROME_VERSION}'
           '/linux-arm64/chrome-linux-arm64.zip')
    archive = run(['curl', '--fail', '--silent', '--show-error', '--location',
                   '--proto', '=https', '--tlsv1.2', '--connect-timeout', '15',
                   '--max-time', '180', url], timeout=190)
    require(hashlib.sha256(archive).hexdigest() == CHROME_SHA256)
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        for item in zipped.infolist():
            target = (dest / item.filename).resolve()
            require(target.is_relative_to(dest))
        zipped.extractall(dest)
        for item in zipped.infolist():
            if not item.is_dir():
                (dest / item.filename).chmod((item.external_attr >> 16) & 0o755 or 0o644)
    chrome = dest / 'chrome-linux-arm64/chrome'
    chrome.chmod(0o755)
    # Playwright installs system libraries only in ephemeral hosted CI runners.
    run([python, '-m', 'playwright', 'install-deps', 'chromium'], timeout=300)


class Roundtrip:
    def __init__(self, temp, evidence):
        self.project = 'ls-functional-' + secrets.token_hex(16)
        self.env = clean_environment()
        self.temp = Path(temp)
        self.evidence = evidence
        self.owned = False
        self.admin_password = secrets.token_urlsafe(32)
        self.marker = 'synthetic-' + secrets.token_hex(16)
        self.image = os.environ['APP_IMAGE']
        self.browser_options, self.browser_version = browser_options(os.environ['FUNCTIONAL_CHROME'])
        self.source = run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).decode().strip()
        inspect = json.loads(run(['docker', 'image', 'inspect', self.image]))[0]
        require(inspect['Config']['Labels']['io.omnestack.limesurvey.upstream-revision'] == UPSTREAM)
        self.image_id = inspect['Id']
        self.architecture = inspect['Architecture']
        self.image_revision = inspect['Config']['Labels']['org.opencontainers.image.revision']
        require(bool(re.fullmatch(r'sha256:[0-9a-f]{64}', self.image_id)))
        require(bool(re.fullmatch(r'[0-9a-f]{40}', self.source)))
        require(self.image_revision == 'development' or
                bool(re.fullmatch(r'[0-9a-f]{40}', self.image_revision)))
        require(self.architecture in {'arm64', 'amd64'})
        for resource in ('container', 'volume', 'network'):
            require(not run(['docker', resource, 'ls', '-q', '--filter',
                             'label=com.docker.compose.project=' + self.project]).strip())
        envfile = self.temp / 'env'
        envfile.write_text('DB_NAME=limesurvey\nDB_USER=limesurvey\nDB_PASSWORD=' +
                           secrets.token_urlsafe(32) + '\nDB_ROOT_PASSWORD=' +
                           secrets.token_urlsafe(32) + '\nRESEND_API_KEY=synthetic-disabled\n'
                           'RESEND_FROM_EMAIL=probe@example.invalid\n')
        envfile.chmod(0o600)
        override = self.temp / 'override.json'
        override.write_text(json.dumps({'services': {'nginx': {'ports': [
            {'target': 80, 'published': '0', 'host_ip': '127.0.0.1'}]}}}))
        self.command = ['docker', 'compose', '--project-name', self.project,
                        '--env-file', str(envfile), '-f', str(ROOT / 'compose.yaml'),
                        '-f', str(override)]
        config = json.loads(self.compose('config', '--format', 'json'))
        validate_config(config, self.project)
        # Check exact names too: an existing unlabelled volume must never be adopted.
        for resource, specs in (('volume', config['volumes']), ('network', config['networks'])):
            existing = run(['docker', resource, 'ls', '--format', '{{.Name}}']).decode().splitlines()
            require(not set(existing) & {spec['name'] for spec in specs.values()})

    def compose(self, *args, data=None, timeout=180):
        return run(self.command + list(args), data=data, timeout=timeout, env=self.env)

    def wait(self):
        for _ in range(90):
            ids = self.compose('ps', '-q').decode().split()
            if len(ids) == 3:
                state = json.loads(run(['docker', 'inspect'] + ids))
                if all(item['State'].get('Health', {}).get('Status') == 'healthy' for item in state):
                    app = [item for item in state if item['Config']['Labels']['com.docker.compose.service'] == 'app']
                    require(len(app) == 1 and app[0]['Image'] == self.image_id)
                    return
            time.sleep(2)
        raise GateError('health timeout')

    def api(self, method, *params):
        payload = json.dumps({'method': method, 'params': list(params), 'id': 1}).encode()
        request = urllib.request.Request(self.url + '/index.php?r=admin/remotecontrol',
                                         data=payload, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            require(response.status == 200 and response.geturl() == request.full_url)
            return rpc_result(json.loads(response.read(4 * 1024 * 1024)))

    def authenticate(self):
        key = self.api('get_session_key', 'functionaladmin', self.admin_password)
        require(isinstance(key, str) and bool(re.fullmatch(r'[A-Za-z0-9_~]{32}', key)))
        return key

    def volume_ids(self):
        ids = self.compose('ps', '-q').decode().split()
        state = json.loads(run(['docker', 'inspect'] + ids))
        return sorted((item['Config']['Labels']['com.docker.compose.service'], mount['Destination'],
                       mount['Name']) for item in state for mount in item['Mounts'] if mount['Type'] == 'volume')

    def execute(self):
        self.owned = True
        self.compose('pull', 'db', 'nginx', timeout=300)
        self.compose('up', '-d', '--no-build', '--pull', 'never', timeout=300)
        self.wait()
        # Fresh project volumes alone are insufficient: prove no tables/config.
        count = self.compose('exec', '-T', 'db', 'sh', '-eu', '-c',
            'export MYSQL_PWD=$MARIADB_PASSWORD; mariadb --batch --skip-column-names '
            '--user="$MARIADB_USER" "$MARIADB_DATABASE" --execute="SHOW TABLES"')
        require(not count.strip())
        self.compose('exec', '-T', 'app', 'sh', '-eu', '-c',
                     'test ! -e application/config/config.php')
        configuration = '''<?php return ['components'=>['db'=>[
'class'=>'CDbConnection','connectionString'=>'mysql:host=db;port=3306;dbname='.getenv('DB_NAME'),
'username'=>getenv('DB_USER'),'password'=>getenv('DB_PASSWORD'),'charset'=>'utf8mb4',
'emulatePrepare'=>true,'tablePrefix'=>'lime_']], 'config'=>['RPCInterface'=>'json']];'''
        self.compose('exec', '-T', '--user', 'www-data', 'app', 'sh', '-eu', '-c',
                     'test ! -e application/config/config.php; cat > application/config/config.php',
                     data=configuration.encode())
        # Credentials remain stdin data, never command arguments or log text.
        self.compose('exec', '-T', '--user', 'www-data', 'app', 'php', '-r',
            '$p=json_decode(stream_get_contents(STDIN),true); '
            '$cmd=[PHP_BINARY,"application/commands/console.php","install",'
            '"functionaladmin",$p[0],"Synthetic admin","probe@example.invalid"]; '
            '$r=proc_open($cmd,[0=>["file","/dev/null","r"],1=>["file","/dev/null","w"],'
            '2=>["file","/dev/null","w"]],$pipes); exit(proc_close($r));',
            data=json.dumps([self.admin_password]).encode())
        port = self.compose('port', 'nginx', '80').decode().strip()
        require(bool(re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]*', port)))
        self.url = 'http://' + port
        key = self.authenticate()
        sid = self.api('add_survey', key, 0, 'Synthetic functional probe', 'en', 'A')
        require(type(sid) is int and sid > 0)
        gid = self.api('add_group', key, sid, 'Synthetic probe')
        require(type(gid) is int and gid > 0)
        fixture = self.compose('exec', '-T', 'app', 'cat',
            'tests/data/surveys/limesurvey_question_import_question_test_II.lsq')
        question = self.api('import_question', key, sid, gid,
                            base64.b64encode(fixture).decode(), 'lsq', 'Y', 'SMOKE', 'Synthetic probe')
        require(type(question) is int and question > 0)
        properties = self.api('set_survey_properties', key, sid,
                             {'showwelcome': 'N', 'usecaptcha': 'N', 'access_mode': 'O'})
        require(properties == {'showwelcome': True, 'usecaptcha': True, 'access_mode': True})
        activation = self.api('activate_survey', key, sid)
        require(isinstance(activation, dict) and activation.get('status') == 'OK')
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**self.browser_options)
            context = browser.new_context()
            page = context.new_page()
            page.set_default_timeout(30000)
            page.goto(f'{self.url}/index.php?r=survey/index&sid={sid}&lang=en')
            page.locator('textarea').fill(self.marker)
            page.get_by_role('button', name=re.compile(r'^Submit$', re.I)).click()
            page.get_by_text('Your survey responses have been recorded.').wait_for(state='visible')
            page.screenshot(path=str(self.evidence / 'synthetic-completion.png'))
            context.close()
            browser.close()
        before = exported(self.api('export_responses', key, sid, 'csv', 'en', 'complete', 'code', 'short'), self.marker)
        self.api('release_session_key', key)
        volumes = self.volume_ids()
        self.compose('restart', 'db', 'app', timeout=180)
        self.wait()
        require(self.volume_ids() == volumes)
        require(json.loads(run(['docker', 'image', 'inspect', self.image]))[0]['Id'] == self.image_id)
        key = self.authenticate()
        after = exported(self.api('export_responses', key, sid, 'csv', 'en', 'complete', 'code', 'short'), self.marker)
        require(before == after)
        self.api('release_session_key', key)
        return {'gate': 'PASS', 'source_commit': self.source, 'image_id': self.image_id,
                'image_revision': self.image_revision, 'upstream_commit': UPSTREAM,
                'platform': 'linux/' + self.architecture, 'browser_version': self.browser_version,
                'completed_count': 1, 'response_id_sha256': hashlib.sha256(before[0].encode()).hexdigest(),
                'export_sha256': before[1], 'restart': 'PASS'}

    def cleanup(self):
        if self.owned:
            self.compose('down', '--volumes', '--remove-orphans', timeout=180)
            for resource in ('container', 'volume', 'network'):
                require(not run(['docker', resource, 'ls', '-q', '--filter',
                    'label=com.docker.compose.project=' + self.project]).strip())


def roundtrip():
    evidence = Path(os.environ['FUNCTIONAL_EVIDENCE']).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    receipt = evidence / 'functional-receipt.json'
    receipt.unlink(missing_ok=True)
    (evidence / 'synthetic-completion.png').unlink(missing_ok=True)
    runner = None
    try:
        with tempfile.TemporaryDirectory(prefix='ls-functional-') as temp:
            try:
                runner = Roundtrip(temp, evidence)
                result = runner.execute()
            finally:
                if runner is not None:
                    # Finish finite cleanup even if a second interrupt arrives.
                    signal.signal(signal.SIGINT, signal.SIG_IGN)
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    runner.cleanup()
        receipt.write_text(json.dumps(result, indent=2) + '\n')
        print('functional_roundtrip=PASS')
    except BaseException:
        receipt.unlink(missing_ok=True)
        raise


class SelfTest(unittest.TestCase):
    def test_rpc_errors(self):
        for value in ({}, {'id': 1, 'error': 'secret', 'result': 'x'},
                      {'id': 1, 'result': {'status': 'Invalid session key'}},
                      {'id': 2, 'result': 'x'}, {'id': 1, 'result': None},
                      {'id': 1, 'result': {'error_code': 3}},
                      {'id': 1, 'result': {'errors': ['secret']}}):
            with self.subTest(value=value), self.assertRaises(GateError):
                rpc_result(value)
        self.assertEqual(rpc_result({'id': 1, 'result': {'status': 'OK'}}), {'status': 'OK'})

    def test_session_key_contract(self):
        from unittest.mock import Mock
        runner = Roundtrip.__new__(Roundtrip)
        runner.admin_password = 'synthetic-password'
        key = 'A' * 30 + '_~'
        runner.api = Mock(return_value=key)
        self.assertEqual(runner.authenticate(), key)
        for value in ('', 'A' * 31, 'A' * 33, 'A' * 31 + '+', 'A' * 31 + '/', None):
            runner.api = Mock(return_value=value)
            with self.subTest(value=value), self.assertRaises(GateError):
                runner.authenticate()

    def test_completed_export(self):
        def encode(value):
            return base64.b64encode(value.encode()).decode()
        good = '\ufeffid;submitdate;SMOKE\r\n1;2026-10-10;synthetic\r\n'
        self.assertEqual(exported(encode(good), 'synthetic')[0], '1')
        for bad in (good + '2;2026-10-10;synthetic\n', good.replace(';2026-10-10;', ';;'),
                    good.replace('synthetic', 'wrong'), good.replace('1;', '0;'),
                    'id;submitdate;SMOKE;SMOKE\n1;date;synthetic;synthetic\n', 'secret'):
            with self.subTest(), self.assertRaises((GateError, ValueError)):
                exported(encode(bad), 'synthetic')
        with self.assertRaises(ValueError):
            exported('!!!', 'synthetic')

    def test_project_boundary(self):
        safe_project('ls-functional-' + 'a' * 32)
        for project in ('production', 'limesurvey-release-artifact', 'ls-functional-x', ''):
            with self.assertRaises(GateError):
                safe_project(project)

    def test_browser_policy(self):
        from unittest.mock import patch
        local = '/home/gion/.cache/chrome-for-testing/stable/chrome-linux64/chrome'
        with patch.dict(os.environ, {}, clear=True), patch('os.geteuid', return_value=1000), \
                patch.object(Path, 'is_file', return_value=True), \
                patch(__name__ + '.run', return_value=b'Google Chrome for Testing 155.0.8059.39\n'):
            options, version = browser_options(local)
            self.assertTrue(options['chromium_sandbox'])
            self.assertNotIn('args', options)
            for executable in ('/usr/bin/chromium', '/tmp/chrome-linux-arm64/chrome', '/tmp/chrome'):
                with self.assertRaises(GateError):
                    browser_options(executable)
            with patch('os.geteuid', return_value=0), self.assertRaises(GateError):
                browser_options(local)
            with patch(__name__ + '.run', return_value=b'Chromium 155.0.0.0'), self.assertRaises(GateError):
                browser_options(local)

    def test_failure_output_is_sanitized(self):
        with tempfile.TemporaryDirectory() as temp:
            env = dict(os.environ, FUNCTIONAL_EVIDENCE=temp, APP_IMAGE='synthetic-secret-never-log')
            env.pop('FUNCTIONAL_CHROME', None)
            result = subprocess.run([sys.executable, str(Path(__file__)), 'run'],
                                    env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'functional_roundtrip=FAIL (details suppressed)\n')
            self.assertFalse((Path(temp) / 'functional-receipt.json').exists())

    def test_reject_config(self):
        from copy import deepcopy
        project = 'ls-functional-' + 'b' * 32
        volumes = {str(n): {'name': project + '_' + str(n)} for n in range(7)}
        config = {'name': project, 'volumes': volumes, 'networks': {
            'backend': {'name': project + '_backend', 'internal': True}}, 'services': {
            name: {'environment': {}, 'volumes': []} for name in ('db', 'app', 'nginx')}}
        config['services']['db']['networks'] = {'backend': None}
        config['services']['nginx']['ports'] = [{'host_ip': '127.0.0.1', 'target': 80, 'published': '0'}]
        validate_config(config, project)
        for change in ('external', 'production_name', 'driver', 'db_port', 'public_port', 'bind', 'remote_db', 'host_network', 'public_backend', 'db_egress'):
            value = deepcopy(config)
            if change == 'external':
                value['volumes']['0']['external'] = True
            elif change == 'production_name':
                value['volumes']['0']['name'] = 'production_data'
            elif change == 'driver':
                value['volumes']['0']['driver_opts'] = {'device': '/production'}
            elif change == 'db_port':
                value['services']['db']['ports'] = [{'host_ip': '127.0.0.1', 'target': 3306, 'published': '0'}]
            elif change == 'public_port':
                value['services']['nginx']['ports'][0]['host_ip'] = '0.0.0.0'
            elif change == 'bind':
                value['services']['app']['volumes'] = [{'type': 'bind', 'source': '/production'}]
            elif change == 'host_network':
                value['services']['db']['network_mode'] = 'host'
            elif change == 'public_backend':
                value['networks']['backend']['internal'] = False
            elif change == 'db_egress':
                value['services']['db']['networks']['egress'] = None
            else:
                value['services']['app']['environment']['DB_HOST'] = 'production'
            with self.subTest(change=change), self.assertRaises(GateError):
                validate_config(value, project)

    def test_receipt_failure_invalidation(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'functional-receipt.json'
            path.write_text('{"gate":"PASS"}')
            with patch.dict(os.environ, {'FUNCTIONAL_EVIDENCE': temp}), \
                    patch(__name__ + '.Roundtrip', side_effect=GateError('secret')):
                with self.assertRaises(GateError):
                    roundtrip()
            self.assertFalse(path.exists())

    def test_reject_environment(self):
        from unittest.mock import patch
        for name in ('COMPOSE_PROJECT_NAME', 'COMPOSE_FILE', 'ENV_FILE', 'KEEP_SMOKE_STACK',
                     'DOCKER_HOST', 'DOCKER_CONTEXT'):
            with patch.dict(os.environ, {name: 'production'}), self.assertRaises(GateError):
                clean_environment()


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['self-test']:
            unittest.main(argv=[sys.argv[0]])
        elif len(sys.argv) == 3 and sys.argv[1] == 'bootstrap':
            bootstrap(sys.argv[2])
        elif sys.argv[1:] == ['run']:
            def interrupted(signum, frame):
                raise GateError('interrupted')
            signal.signal(signal.SIGTERM, interrupted)
            signal.signal(signal.SIGINT, interrupted)
            roundtrip()
        else:
            raise GateError('unsupported command')
    except Exception:
        print('functional_roundtrip=FAIL (details suppressed)', file=sys.stderr)
        sys.exit(1)
