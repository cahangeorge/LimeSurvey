#!/usr/bin/env python3
"""Bounded selected-triple staging preparation and private operational proof."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import tempfile
import copy
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
CHROME = '/home/gion/.cache/chrome-for-testing/stable/chrome-linux64/chrome'
VOLUMES = {'db': '/var/lib/mysql', 'code': '/var/www/html', 'config': '/var/www/html/application/config',
           'upload': '/var/www/html/upload', 'plugins': '/var/www/html/plugins',
           'themes': '/var/www/html/themes', 'runtime': '/var/www/html/tmp'}
IMAGES = {'app': 'php', 'nginx': 'nginx', 'db': 'mariadb'}
REPOSITORIES = {'php': 'ghcr.io/cahangeorge/limesurvey', 'nginx': 'ghcr.io/cahangeorge/limesurvey-nginx',
                'mariadb': 'ghcr.io/cahangeorge/limesurvey-mariadb'}
LABEL = 'io.omnestack.limesurvey.operational-owner'


class GateError(ValueError):
    pass


def require(condition):
    if not condition:
        raise GateError('operational requirement failed')


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protected(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
    return path


def load_private(path, expected=None):
    path = protected(path)
    raw = path.read_bytes()
    if expected is not None:
        require(isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected)
                and hashlib.sha256(raw).hexdigest() == expected)
    return json.loads(raw)


def save_private(path, value):
    path = Path(path)
    require(path.parent.is_dir() and not path.is_symlink())
    if path.exists(): protected(path)
    temporary = path.with_name(path.name + '.tmp-' + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def recent(value, seconds=86400):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(stamp.tzinfo is not None and -300 <= (datetime.now(timezone.utc) - stamp).total_seconds() <= seconds)


def command(arguments, data=None, timeout=120, env=None):
    result = subprocess.run(arguments, input=data, capture_output=True, timeout=timeout, env=env)
    require(result.returncode == 0)
    return result.stdout


def docker(*args, data=None, timeout=120):
    return command(['docker', *args], data=data, timeout=timeout)


def compare_configuration(expected, actual, project):
    actual = copy.deepcopy(actual)
    provider = {'coolify.managed': 'true', 'coolify.applicationUuid': project, 'coolify.type': 'application'}
    require(set(actual.get('services', {})) == set(expected.get('services', {})) == set(IMAGES))
    for service in actual['services'].values():
        labels = service.get('labels', {})
        require(isinstance(labels, dict))
        injected = set(labels) & set(provider)
        if injected:
            require(injected == set(provider) and all(labels[key] == value for key, value in provider.items()))
            for key in provider: del labels[key]
            if not labels: service.pop('labels', None)
    require(actual == expected)


def configuration_source(value, rendered=False):
    repository = Path(value['repository_root'])
    adapter = repository / 'deploy/staging.compose.yaml'
    require(not adapter.is_symlink() and adapter.is_file())
    require(command(['git', '-C', str(repository), 'rev-parse', 'HEAD']).decode().strip()
            == value['configuration_commit'])
    committed_adapter = None
    for relative, expected in (('deploy/staging.compose.yaml', value['adapter_sha256']),
                               ('docker/nginx/default.conf', value['nginx_sha256'])):
        target = repository / relative
        require(not target.is_symlink() and target.is_file())
        committed = command(['git', '-C', str(repository), 'show', value['configuration_commit'] + ':' + relative])
        require(hashlib.sha256(committed).hexdigest() == expected)
        if relative.startswith('deploy/'):
            committed_adapter = committed
            if not rendered: require(target.read_bytes() == committed)
        else:
            require(target.read_bytes() == committed)
    if rendered:
        env_file = protected(repository / '.env')
        generated = repository / 'docker-compose.yaml'
        require(generated.is_file() and not generated.is_symlink())
        env = {key: val for key, val in os.environ.items()
               if not key.startswith(('DELIVERY_', 'STAGING_', 'COMPOSE_'))}
        env.update(adapter_environment(value))
        def render(path):
            return json.loads(command(['docker', 'compose', '--project-directory', str(repository),
                '--env-file', str(env_file), '--project-name', value['project'], '-f', str(path),
                'config', '--format', 'json'], env=env))
        with tempfile.TemporaryDirectory(prefix='ls-reviewed-adapter-') as directory:
            source = Path(directory) / 'adapter.yaml'
            descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream: stream.write(committed_adapter)
            expected = render(source)
            compare_configuration(expected, render(adapter), value['project'])
            compare_configuration(expected, render(generated), value['project'])


def runtime_options(service, item, image):
    host = item['HostConfig']
    memory, cpu = {'db': (1073741824, 1000000000), 'app': (536870912, 1000000000),
                   'nginx': (134217728, 250000000)}[service]
    require(host.get('Memory') == memory and host.get('NanoCpus') == cpu
            and not host.get('CpuQuota') and not host.get('CpuPeriod')
            and host.get('RestartPolicy') == {'Name': 'unless-stopped', 'MaximumRetryCount': 0}
            and not host.get('SecurityOpt') and not host.get('CapDrop')
            and host.get('ReadonlyRootfs', False) is (service == 'nginx'))
    for field in ('Cmd', 'Entrypoint', 'User', 'WorkingDir', 'StopSignal'):
        actual, expected = item['Config'].get(field), image['Config'].get(field)
        if field in ('User', 'WorkingDir'): actual, expected = actual or '', expected or ''
        require(actual == expected)
    tests = {'db': ['CMD', 'healthcheck.sh', '--connect', '--innodb_initialized'],
             'app': ['CMD-SHELL', 'kill -0 1 && php-fpm -t'],
             'nginx': ['CMD', 'wget', '--quiet', '--spider', 'http://127.0.0.1/healthz']}
    expected = {'Test': tests[service], 'Interval': 10000000000, 'Timeout': 5000000000,
                'Retries': 12 if service == 'db' else 6,
                'StartPeriod': {'db': 30000000000, 'app': 20000000000, 'nginx': 10000000000}[service]}
    actual = dict(item['Config'].get('Healthcheck') or {})
    require(actual.pop('StartInterval', 0) == 0 and actual == expected)


def manifest(path, expected, local_configuration=True):
    value = load_private(path, expected)
    require(value.get('schema_version') == 1 and value.get('environment') == 'staging')
    project = value['project']
    require(isinstance(project, str) and re.fullmatch(r'[a-z0-9]{20,64}', project))
    require(re.fullmatch(r'[0-9a-f]{40}', value['configuration_commit']))
    require(re.fullmatch(r'[0-9a-f]{64}', value['adapter_sha256']))
    require(type(value['port']) is int and 1024 <= value['port'] <= 65535)
    require(set(value['images']) == set(REPOSITORIES) and set(value['config_digests']) == set(REPOSITORIES))
    for kind, repository in REPOSITORIES.items():
        require(re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', value['images'][kind]))
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', value['config_digests'][kind]))
    app_digest = value['images']['php'].split(':')[-1]
    require(set(value['volumes']) == set(VOLUMES) and set(value['networks']) == {'backend', 'frontend'})
    for kind, name in value['volumes'].items():
        require(name == project + '-stage-' + kind + (('-' + app_digest) if kind not in ('db', 'upload') else ''))
    for kind, name in value['networks'].items(): require(name == project + '-stage-' + kind)
    repository = Path(value['repository_root'])
    require(repository.is_absolute())
    config = repository / 'docker/nginx/default.conf'
    if local_configuration:
        configuration_source(value, rendered=(repository / 'docker-compose.yaml').exists())
    state = Path(value['state_file'])
    require(state.is_absolute() and state.parent.resolve() == Path(path).resolve().parent)
    admission = value['admission']
    receipt = load_private(admission['receipt'], admission['receipt_sha256'])
    bundle = load_private(admission['bundle'], admission['bundle_sha256'])
    require(receipt.get('status') == 'ARTIFACT_BUNDLE_ADMITTED' and receipt.get('staging_deployable') is False
            and receipt.get('expected_bundle_sha256') == admission['bundle_sha256']
            and receipt.get('source_commit') == bundle['source_commit']
            and receipt.get('upstream_commit') == bundle['upstream_commit'] == 'c5a2ac817396220e054efc3fd26b84cafb92b36f'
            and set(receipt['components']) == set(REPOSITORIES) and set(bundle['components']) == set(REPOSITORIES))
    recent(receipt['checked_at'], 3600)
    for kind in REPOSITORIES:
        candidate = bundle['components'][kind]; accepted = receipt['components'][kind]
        require(candidate['image'] == accepted['image'] == value['images'][kind]
                and candidate['image_config_digest'] == accepted['image_config_digest'] == value['config_digests'][kind]
                and candidate['release_sha256'] == accepted['release_sha256']
                and candidate['release_run'] == accepted['release_run']
                and accepted['source_commit'] == bundle['source_commit']
                and accepted.get('scan') == accepted.get('signatures') == 'PASS')
        evidence = Path(candidate['evidence_directory'])
        require(file_hash(evidence / 'release.json') == candidate['release_sha256'])
        for name, digest in candidate['evidence_sha256'].items():
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name))
            target = evidence / name
            require(not target.is_symlink() and file_hash(target) == digest)
        for name in ('scan.json', 'candidate-scan.json'):
            if name in candidate['evidence_sha256']: recent(json.loads((evidence / name).read_text())['CreatedAt'])
        for name in ('db.json', 'candidate-db.json'):
            if name in candidate['evidence_sha256']:
                db = json.loads((evidence / name).read_text())
                for field in ('UpdatedAt', 'DownloadedAt'): recent(db[field])
    value['_manifest_sha256'] = expected
    return value


@contextmanager
def lock(value):
    path = Path(value['state_file'] + '.lock')
    require(not path.is_symlink())
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        require(stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600)
        try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise GateError('operation already locked') from None
        yield
    finally:
        os.close(descriptor)


def adapter_environment(value):
    result = {'DELIVERY_PROJECT': value['project'], 'DELIVERY_APP_IMAGE': value['images']['php'],
              'DELIVERY_NGINX_IMAGE': value['images']['nginx'], 'DELIVERY_DB_IMAGE': value['images']['mariadb'],
              'DELIVERY_REPOSITORY_ROOT': value['repository_root'], 'DELIVERY_PORT': str(value['port'])}
    result.update({'DELIVERY_' + kind.upper() + '_VOLUME': name for kind, name in value['volumes'].items()})
    result.update({'DELIVERY_' + kind.upper() + '_NETWORK': name for kind, name in value['networks'].items()})
    return result


def resource(kind, name):
    values = json.loads(docker(kind, 'inspect', name))
    require(len(values) == 1)
    item = values[0]
    return {'name': item['Name'], 'id': item.get('Id', item['Name']),
            'created_at': item.get('CreatedAt', item.get('Created')), 'labels': item.get('Labels') or {},
            'internal': item.get('Internal')}


def owned_resources(value, state, complete=True):
    require(state.get('manifest_sha256') == value['_manifest_sha256'])
    expected_names = set(value['volumes'].values()) | set(value['networks'].values())
    require(set(state['resources']) <= expected_names)
    if complete: require(set(state['resources']) == expected_names)
    for kind, names in (('volume', value['volumes']), ('network', value['networks'])):
        for name in names.values():
            if name not in state['resources']: continue
            actual = resource(kind, name)
            require(actual == state['resources'][name] and actual['labels'].get(LABEL) == value['_manifest_sha256'])
            if kind == 'network': require(actual['internal'] is True)


def image_identity(value, kind, inspected):
    """Resolve classic/config or containerd/leaf IDs through signed publisher bytes."""
    bundle = load_private(value['admission']['bundle'], value['admission']['bundle_sha256'])
    expected = bundle['components'][kind]
    require(expected['image'] == value['images'][kind]
            and expected['image_config_digest'] == value['config_digests'][kind])
    root = Path(expected['evidence_directory'])
    raw = {}
    for name in ('registry-manifest.json', 'image.json'):
        path = root / name
        require(not path.is_symlink())
        raw[name] = path.read_bytes()
        require(hashlib.sha256(raw[name]).hexdigest() == expected['evidence_sha256'][name])
    digest = value['images'][kind].split('@')[1]
    config_digest = value['config_digests'][kind]
    require('sha256:' + hashlib.sha256(raw['registry-manifest.json']).hexdigest() == digest)
    registry = json.loads(raw['registry-manifest.json'])
    require(registry.get('schemaVersion') == 2 and registry.get('mediaType') in (
        'application/vnd.docker.distribution.manifest.v2+json', 'application/vnd.oci.image.manifest.v1+json')
        and registry['config']['digest'] == config_digest and isinstance(registry.get('layers'), list)
        and registry['layers'])
    publisher = json.loads(raw['image.json'])
    require(isinstance(publisher, list) and len(publisher) == 1)
    publisher = publisher[0]
    require(publisher.get('Id') == config_digest and publisher.get('Os') == 'linux'
            and publisher.get('Architecture') == 'arm64' and value['images'][kind] in publisher.get('RepoDigests', []))
    require(isinstance(inspected, list) and len(inspected) == 1)
    image = inspected[0]
    require(image.get('Os') == 'linux' and image.get('Architecture') == 'arm64'
            and value['images'][kind] in image.get('RepoDigests', []))
    descriptor = image.get('Descriptor')
    if 'Descriptor' in image:
        # A descriptor cannot contradict the leaf even when Docker reports a classic config ID.
        require(isinstance(descriptor, dict) and descriptor.get('digest') == digest
                and descriptor.get('mediaType') == registry['mediaType'])
        if 'platform' in descriptor:
            require(isinstance(descriptor['platform'], dict) and descriptor['platform'].get('os') == 'linux'
                    and descriptor['platform'].get('architecture') == 'arm64')
    require(image.get('Id') == config_digest or (image.get('Id') == digest and isinstance(descriptor, dict)))
    rootfs = publisher['RootFS']
    require(rootfs.get('Type') == 'layers' and isinstance(rootfs.get('Layers'), list)
            and len(rootfs['Layers']) == len(registry['layers'])
            and all(isinstance(layer, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', layer) for layer in rootfs['Layers'])
            and image.get('RootFS') == rootfs)
    # These OCI-derived config fields are stable across Docker API versions. Deprecated
    # Docker attach/hostname/intermediate-image fields do not define the selected runtime.
    for field in ('Labels', 'Env', 'Cmd', 'Entrypoint', 'User', 'WorkingDir', 'ExposedPorts',
                  'Volumes', 'Healthcheck', 'StopSignal', 'Shell', 'OnBuild'):
        actual = image['Config'].get(field)
        expected_config = publisher['Config'].get(field)
        # Both API representations mean the OCI default for these string fields.
        if field in ('User', 'WorkingDir'):
            actual = '' if actual is None else actual
            expected_config = '' if expected_config is None else expected_config
        require(actual == expected_config)
    return image['Id']


def prepare(value):
    state_path = Path(value['state_file'])
    require(not state_path.exists())
    # Refuse any collision before creating the first resource; never reuse production data.
    existing_volumes = docker('volume', 'ls', '--format', '{{.Name}}').decode().splitlines()
    existing_networks = docker('network', 'ls', '--format', '{{.Name}}').decode().splitlines()
    require(not set(existing_volumes) & set(value['volumes'].values())
            and not set(existing_networks) & set(value['networks'].values()))
    image_ids = {kind: image_identity(value, kind, json.loads(docker('image', 'inspect', value['images'][kind])))
                 for kind in REPOSITORIES}
    state = {'schema_version': 1, 'manifest_sha256': value['_manifest_sha256'], 'status': 'PREPARING',
             'resources': {}, 'seed_container': None, 'containers': {}}
    save_private(state_path, state)
    for kind, names in (('network', value['networks']), ('volume', value['volumes'])):
        for name in names.values():
            args = [kind, 'create', '--label', LABEL + '=' + value['_manifest_sha256']]
            if kind == 'network': args += ['--internal']
            docker(*args, name)
            state['resources'][name] = resource(kind, name); save_private(state_path, state)
    mounts = []
    for kind in VOLUMES:
        if kind != 'db': mounts += ['--mount', 'type=volume,src=' + value['volumes'][kind] + ',dst=/seed/' + kind]
    # Fixed paths only. Empty destination proof precedes every copy; no hidden volume copy-up.
    script = '\n'.join('test -z "$(ls -A /seed/' + kind + ')"; cp -a ' + source + '/. /seed/' + kind + '/'
                       for kind, source in VOLUMES.items() if kind != 'db')
    script += '\ncp -a /opt/limesurvey-managed-plugins/ResendEmail /seed/plugins/ResendEmail\n'
    identifier = docker('create', '--network', 'none', '--user', '0', '--label', LABEL + '=' + value['_manifest_sha256'],
                        '--entrypoint', 'sh', *mounts, value['images']['php'], '-eu', '-c', script).decode().strip()
    require(re.fullmatch(r'[0-9a-f]{64}', identifier)); state['seed_container'] = identifier; save_private(state_path, state)
    docker('start', '-a', identifier, timeout=180)
    inspected = json.loads(docker('inspect', identifier))[0]
    require(inspected['State']['Status'] == 'exited' and inspected['State']['ExitCode'] == 0
            and inspected['Config']['Labels'].get(LABEL) == value['_manifest_sha256']
            and inspected['Image'] == image_ids['php'] and inspected['Config']['Image'] == value['images']['php'])
    docker('rm', identifier)
    state['seed_container'] = None; state['status'] = 'PREPARED'; save_private(state_path, state)
    return {'status': 'PREPARED', 'manifest_sha256': value['_manifest_sha256'], 'adapter_environment': adapter_environment(value)}


def runtime(value, state, require_healthy=True):
    configuration_source(value, rendered=True)
    owned_resources(value, state)
    images = {kind: json.loads(docker('image', 'inspect', value['images'][kind])) for kind in REPOSITORIES}
    image_ids = {kind: image_identity(value, kind, images[kind]) for kind in REPOSITORIES}
    identifiers = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + value['project']).decode().split()
    require(len(identifiers) == 3)
    inspected = json.loads(docker('inspect', *identifiers))
    result = {}
    for item in inspected:
        service = item['Config']['Labels'].get('com.docker.compose.service')
        require(service in IMAGES and service not in result and re.fullmatch(r'[0-9a-f]{64}', item['Id']))
        require(item['Config']['Labels'].get('com.docker.compose.project') == value['project']
                and item['Image'] == image_ids[IMAGES[service]]
                and item['Config']['Image'] == value['images'][IMAGES[service]])
        runtime_options(service, item, images[IMAGES[service]][0])
        if require_healthy: require(item['State'].get('Health', {}).get('Status') == 'healthy')
        networks = item['NetworkSettings']['Networks']
        expected_networks = {'backend', 'frontend'} if service == 'nginx' else {'backend'}
        require(set(networks) == {value['networks'][kind] for kind in expected_networks})
        for kind in expected_networks:
            name = value['networks'][kind]
            require(networks[name]['NetworkID'] == state['resources'][name]['id'])
        require(item['HostConfig'].get('Privileged', False) is False
                and not item['HostConfig'].get('CapAdd') and not item['HostConfig'].get('Devices')
                and item['HostConfig'].get('PidMode', '') == '')
        mounts = item['Mounts']
        temporary = [mount['Destination'] for mount in mounts if mount['Type'] == 'tmpfs']
        require(set(temporary) <= ({'/var/cache/nginx', '/var/run'} if service == 'nginx' else set()))
        expected_volumes = set(VOLUMES) - {'db'} if service == 'app' else (
            {'db'} if service == 'db' else {'code', 'upload', 'plugins', 'themes', 'runtime'})
        actual_volumes = [mount for mount in mounts if mount['Type'] == 'volume']
        require(len(actual_volumes) == len(expected_volumes))
        for kind in expected_volumes:
            matches = [mount for mount in actual_volumes if mount['Destination'] == VOLUMES[kind]]
            require(len(matches) == 1 and matches[0]['Name'] == value['volumes'][kind]
                    and matches[0]['RW'] is (service != 'nginx'))
        binds = [mount for mount in mounts if mount['Type'] == 'bind']
        if service == 'nginx':
            require(len(binds) == 1 and binds[0]['Destination'] == '/etc/nginx/conf.d/default.conf'
                    and binds[0]['Source'] == str(Path(value['repository_root']) / 'docker/nginx/default.conf')
                    and binds[0]['RW'] is False and item['HostConfig']['ReadonlyRootfs'] is True)
            ports = item['NetworkSettings']['Ports']
            require(ports == {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(value['port'])}]})
        else:
            require(not binds and not any(item['NetworkSettings']['Ports'].values()))
        require(all(mount['Type'] in ('volume', 'bind', 'tmpfs') for mount in mounts))
        if service == 'app':
            env = dict(entry.split('=', 1) for entry in item['Config']['Env'])
            require(env.get('RESEND_API_KEY') == '' and env.get('DB_HOST') == 'db')
        result[service] = {'id': item['Id'], 'image_id': item['Image'],
                           'image_config_digest': value['config_digests'][IMAGES[service]],
                           'mounts': sorted([mount['Destination'], mount.get('Name', mount.get('Source')), mount['RW']]
                                            for mount in mounts if mount['Type'] in ('volume', 'bind')),
                           'networks': sorted(networks)}
    require(set(result) == set(IMAGES))
    if state.get('containers'): require(result == state['containers'])
    return result


def snapshot(value):
    state = load_private(value['state_file']); containers = runtime(value, state)
    nginx_id = containers['nginx']['id']
    config = docker('exec', nginx_id, 'cat', '/etc/nginx/conf.d/default.conf')
    require(hashlib.sha256(config).hexdigest() == value['nginx_sha256'])
    docker('exec', nginx_id, 'nginx', '-t')
    db_id = containers['db']['id']
    schema = docker('exec', db_id, 'sh', '-eu', '-c',
        'export MYSQL_PWD=$MARIADB_PASSWORD; mariadb --batch --skip-column-names '
        '--user="$MARIADB_USER" "$MARIADB_DATABASE" --execute="SELECT stg_value FROM lime_settings_global WHERE stg_name=\'DBVersion\'"')
    require(schema.strip() == b'717')
    return {'schema_version': 1, 'status': 'RUNTIME_SNAPSHOT_VERIFIED', 'manifest_sha256': value['_manifest_sha256'],
            'checked_at': datetime.now(timezone.utc).isoformat(), 'containers': containers,
            'resources': state['resources'], 'configuration_commit': value['configuration_commit'],
            'adapter_sha256': value['adapter_sha256'], 'schema': 717, 'nginx_sha256': value['nginx_sha256'], 'mail': 'DISABLED'}


def initialize(value, credentials):
    state = load_private(value['state_file']); require(state['status'] == 'PREPARED' and not state['containers'])
    containers = runtime(value, state)
    state['containers'] = containers; state['status'] = 'INITIALIZING'; save_private(value['state_file'], state)
    count = docker('exec', containers['db']['id'], 'sh', '-eu', '-c',
        'export MYSQL_PWD=$MARIADB_PASSWORD; mariadb --batch --skip-column-names '
        '--user="$MARIADB_USER" "$MARIADB_DATABASE" --execute="SHOW TABLES"')
    require(not count.strip())
    app = containers['app']['id']
    docker('exec', app, 'sh', '-eu', '-c', 'test ! -e application/config/config.php')
    auth = load_private(credentials); require(isinstance(auth['admin_user'], str) and re.fullmatch(r'[A-Za-z0-9_]{3,40}', auth['admin_user'])
                                            and isinstance(auth['admin_password'], str) and len(auth['admin_password']) >= 24)
    configuration = "<?php return ['components'=>['db'=>['class'=>'DbConnection','connectionString'=>'mysql:host=db;port=3306;dbname='.getenv('DB_NAME'),'username'=>getenv('DB_USER'),'password'=>getenv('DB_PASSWORD'),'charset'=>'utf8mb4','emulatePrepare'=>true,'tablePrefix'=>'lime_']], 'config'=>['RPCInterface'=>'json']];"
    docker('exec', '-i', '--user', 'www-data', app, 'sh', '-eu', '-c',
           'test ! -e application/config/config.php; cat > application/config/config.php', data=configuration.encode())
    installer = '$p=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR); $_SERVER["argv"]=$GLOBALS["argv"]=["application/commands/console.php","install",$p[0],$p[1],"Synthetic admin","probe@example.invalid"]; $_SERVER["argc"]=$GLOBALS["argc"]=count($_SERVER["argv"]); unset($p); require "application/commands/console.php";'
    docker('exec', '-i', '--user', 'www-data', app, 'php', '-r', installer,
           data=json.dumps([auth['admin_user'], auth['admin_password']]).encode(), timeout=180)
    state['containers'] = containers; state['status'] = 'INITIALIZED'; save_private(value['state_file'], state)
    return snapshot(value)


def restart(value):
    state = load_private(value['state_file']); require(state['status'] == 'INITIALIZED' and set(state['containers']) == set(IMAGES))
    before = snapshot(value)
    docker('restart', *(state['containers'][kind]['id'] for kind in sorted(IMAGES)), timeout=180)
    deadline = time.monotonic() + 180
    while True:
        try:
            after = snapshot(value); break
        except GateError:
            require(time.monotonic() < deadline); time.sleep(2)
    require(before['containers'] == after['containers'] and before['resources'] == after['resources'])
    after['restart'] = 'PASS'
    return after


def cleanup_stage(value):
    state = load_private(value['state_file']); owned_resources(value, state, complete=False)
    # Explicit recorded IDs only. Unknown runtime containers preserve the failed state.
    found = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + value['project']).decode().split()
    expected = {item['id'] for item in state['containers'].values()}
    require(set(found) == expected)
    if expected:
        runtime(value, state, require_healthy=False)
        docker('rm', '-f', *sorted(expected))
    seed = state.get('seed_container')
    if seed:
        item = json.loads(docker('inspect', seed))[0]
        require(item['Id'] == seed and item['Config']['Labels'].get(LABEL) == value['_manifest_sha256'])
        docker('rm', '-f', seed)
    for kind, names in (('volume', value['volumes']), ('network', value['networks'])):
        for name in names.values():
            if name in state['resources']: docker(kind, 'rm', name)
    state['status'] = 'CLEANED'; save_private(value['state_file'], state)
    return {'status': 'CLEANED', 'manifest_sha256': value['_manifest_sha256']}


def smoke_module():
    spec = importlib.util.spec_from_file_location('operational_smoke', ROOT / 'tests/functional-smoke.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def persistence_before(value, previous, proof, url):
    require(previous.get('status') == 'PROBE_BEFORE_PASS' and previous['manifest_sha256'] == value['_manifest_sha256']
            and previous['url'] == url and previous['containers'] == proof['containers']
            and previous['resources'] == proof['resources'] and proof.get('restart') == 'PASS')


def persistence_after(previous, response_id, exported_sha):
    require(previous['export_sha256'] == exported_sha
            and previous['response_id_sha256'] == hashlib.sha256(response_id.encode()).hexdigest())


def probe(value, phase, url, credentials, receipt_path, snapshot_path, snapshot_sha):
    require(phase in ('before', 'after'))
    parsed = urlsplit(url)
    require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port is not None
            and parsed.path in ('', '/') and not parsed.query and not parsed.fragment and not parsed.username)
    url = url.rstrip('/')
    proof = load_private(snapshot_path, snapshot_sha)
    require(proof.get('status') == 'RUNTIME_SNAPSHOT_VERIFIED' and proof.get('manifest_sha256') == value['_manifest_sha256']
            and proof.get('configuration_commit') == value['configuration_commit']
            and proof.get('adapter_sha256') == value['adapter_sha256']
            and proof.get('schema') == 717 and proof.get('nginx_sha256') == value['nginx_sha256'] and proof.get('mail') == 'DISABLED')
    recent(proof['checked_at'], 600)
    previous = None
    if phase == 'after':
        previous = load_private(receipt_path)
        persistence_before(value, previous, proof, url)
    else:
        require(not Path(receipt_path).exists())
    auth = load_private(credentials)
    smoke = smoke_module()
    pending = {'schema_version': 1, 'status': 'PROBE_PENDING', 'phase': phase,
               'manifest_sha256': value['_manifest_sha256'], 'checked_at': datetime.now(timezone.utc).isoformat()}
    if previous is not None: pending['previous_before'] = previous
    # Invalidate current eligibility before authentication or any RPC mutation.
    save_private(receipt_path, pending)
    def api(method, *parameters):
        payload = json.dumps({'method': method, 'params': list(parameters), 'id': 1}).encode()
        request = urllib.request.Request(url + '/index.php?r=admin/remotecontrol', data=payload,
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            require(response.status == 200 and response.geturl() == request.full_url)
            return smoke.rpc_result(json.loads(response.read(4 * 1024 * 1024)))
    key = api('get_session_key', auth['admin_user'], auth['admin_password'])
    require(isinstance(key, str) and re.fullmatch(r'[A-Za-z0-9_~]{32}', key))
    try:
        if phase == 'before':
            marker = 'operational-' + secrets.token_hex(12)
            sid = api('add_survey', key, 0, 'Synthetic operational probe', 'en', 'A')
            require(type(sid) is int and sid > 0)
            gid = api('add_group', key, sid, 'Synthetic probe'); require(type(gid) is int and gid > 0)
            require(hashlib.sha256(smoke.QUESTION_FIXTURE).hexdigest() == smoke.QUESTION_SHA256)
            question = api('import_question', key, sid, gid, base64.b64encode(smoke.QUESTION_FIXTURE).decode(),
                           'lsq', 'Y', 'SMOKE', 'Synthetic probe'); require(type(question) is int and question > 0)
            require(api('set_survey_properties', key, sid, {'showwelcome': 'N', 'usecaptcha': 'N', 'access_mode': 'O'})
                    == {'showwelcome': True, 'usecaptcha': True, 'access_mode': True})
            require(api('activate_survey', key, sid).get('status') == 'OK')
        else:
            sid, marker = previous['survey_id'], previous['marker']
        from playwright.sync_api import sync_playwright
        options, version = smoke.browser_options(CHROME)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**options)
            context = browser.new_context(); page = context.new_page(); page.set_default_timeout(30000)
            try:
                page.goto(url + '/index.php?r=admin/authentication/sa/login', wait_until='domcontentloaded')
                page.locator('input[name="user"]').fill(auth['admin_user'])
                page.locator('input[name="password"]').fill(auth['admin_password'])
                page.locator('button[type="submit"]').click()
                page.locator('a[href*="authentication/sa/logout"]').first.wait_for(state='attached')
                require(page.locator('input[name="password"]').count() == 0)
                if phase == 'before':
                    page.goto(f'{url}/index.php?r=survey/index&sid={sid}&lang=en')
                    page.locator('textarea').fill(marker)
                    page.get_by_role('button', name=re.compile(r'^Submit$', re.I)).click()
                    page.get_by_text('Your survey responses have been recorded.').wait_for(state='visible')
                screenshot = Path(receipt_path).with_suffix('.' + phase + '.png')
                if screenshot.exists(): protected(screenshot)
                descriptor = os.open(screenshot, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'wb') as stream: stream.write(page.screenshot())
            finally:
                context.close(); browser.close()
        response_id, exported_sha = smoke.exported(api('export_responses', key, sid, 'csv', 'en', 'complete', 'code', 'short'), marker)
        if phase == 'after':
            persistence_after(previous, response_id, exported_sha)
        record = {'schema_version': 1, 'status': 'PROBE_' + phase.upper() + '_PASS',
                  'manifest_sha256': value['_manifest_sha256'], 'checked_at': datetime.now(timezone.utc).isoformat(),
                  'url': url, 'survey_id': sid, 'marker': marker, 'completed_count': 1, 'browser_version': version,
                  'response_id_sha256': hashlib.sha256(response_id.encode()).hexdigest(), 'export_sha256': exported_sha,
                  'containers': proof['containers'], 'resources': proof['resources']}
    finally:
        api('release_session_key', key)
    # A release/cleanup exception leaves the pending receipt and historical proof intact.
    save_private(receipt_path, record)
    return {'status': record['status'], 'manifest_sha256': value['_manifest_sha256'], 'completed_count': 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('snapshot', 'stage', 'probe', 'cleanup-stage'))
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--action', choices=('prepare', 'initialize', 'restart'))
    parser.add_argument('--phase', choices=('before', 'after'))
    parser.add_argument('--url'); parser.add_argument('--credentials', type=Path)
    parser.add_argument('--receipt', type=Path); parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--snapshot-sha256')
    args = parser.parse_args()
    try:
        value = manifest(args.manifest, args.manifest_sha256, local_configuration=args.command != 'probe')
        with lock(value):
            if args.command == 'snapshot': result = snapshot(value)
            elif args.command == 'cleanup-stage': result = cleanup_stage(value)
            elif args.command == 'stage':
                require(args.action is not None)
                result = prepare(value) if args.action == 'prepare' else (
                    initialize(value, args.credentials) if args.action == 'initialize' else restart(value))
            else:
                require(args.phase is not None and args.url and args.credentials and args.receipt and args.snapshot and args.snapshot_sha256)
                result = probe(value, args.phase, args.url, args.credentials, args.receipt, args.snapshot, args.snapshot_sha256)
        if args.command in ('snapshot', 'stage') and args.receipt:
            save_private(args.receipt, result)
            result = {key: result[key] for key in ('status', 'manifest_sha256') if key in result}
            result['receipt_sha256'] = file_hash(args.receipt)
        print(json.dumps(result, indent=2)); return 0
    except Exception:
        # External Docker/HTTP/Playwright errors may contain credentials; never relay them.
        print('operational_delivery=HOLD: invalid, changed, unowned or failed evidence', file=sys.stderr); return 1


if __name__ == '__main__': sys.exit(main())
