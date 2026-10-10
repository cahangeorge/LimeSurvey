#!/usr/bin/env python3
"""Bounded selected-triple staging preparation and private operational proof."""
import argparse
import base64
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
import posixpath
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tarfile
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
    prefix = state.get('database_prefix', 'lime_'); require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', prefix))
    schema = docker('exec', db_id, 'sh', '-eu', '-c',
        'export MYSQL_PWD=$MARIADB_PASSWORD; mariadb --batch --skip-column-names '
        '--user="$MARIADB_USER" "$MARIADB_DATABASE" --execute="SELECT stg_value FROM ' + prefix + 'settings_global WHERE stg_name=\'DBVersion\'"')
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



# Recovery uses one application UUID lock across releases and receipt directories.
LOCK_DIRECTORY = Path('/var/lock')


@contextmanager
def production_lock(application_uuid):
    require(isinstance(application_uuid, str) and re.fullmatch(r'[a-z0-9]{20,64}', application_uuid))
    path = LOCK_DIRECTORY / ('limesurvey-' + application_uuid + '.lock')
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
        try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise GateError('production operation already locked') from None
        yield
    finally: os.close(descriptor)


def recovery_plan(path, digest, rescue=False):
    plan = load_private(path, digest)
    require(plan.get('schema_version') == 1 and re.fullmatch(r'[a-z0-9]{20,64}', plan['application_uuid']))
    parent = Path(path).resolve().parent
    require(Path(plan['state_file']).resolve().parent == parent
            and Path(plan['directory']).resolve().parent == parent
            and Path(plan['directory']).is_absolute())
    require(type(plan.get('ack_timeout')) is int and 30 <= plan['ack_timeout'] <= 1800)
    legacy = load_private(plan['legacy_inspect'], plan['legacy_inspect_sha256'])
    require(isinstance(legacy, list) and len(legacy) == 3)
    services = {}
    for item in legacy:
        name = item['Config']['Labels']['com.docker.compose.service']
        require(name in IMAGES and name not in services
                and item['Config']['Labels']['com.docker.compose.project'] == plan['application_uuid']
                and re.fullmatch(r'[0-9a-f]{64}', item['Id']) and re.fullmatch(r'sha256:[0-9a-f]{64}', item['Image']))
        services[name] = item
    require(set(services) == set(IMAGES))
    source = load_private(plan['legacy_compose'], plan['legacy_compose_sha256'])
    require(set(source['services']) == set(IMAGES))
    if rescue:
        candidate = load_private(plan['candidate_manifest'], plan['candidate_manifest_sha256'])
        candidate['_manifest_sha256'] = plan['candidate_manifest_sha256']
        require(set(candidate['images']) == set(REPOSITORIES))
        for kind, reference in candidate['images'].items():
            require(re.fullmatch(re.escape(REPOSITORIES[kind]) + r'@sha256:[0-9a-f]{64}', reference))
    else:
        candidate = manifest(Path(plan['candidate_manifest']), plan['candidate_manifest_sha256'])
        # Historical staging proof stays immutable; current eligibility belongs to the candidate admission.
        stage = load_private(plan['accepted_stage_manifest'], plan['accepted_stage_manifest_sha256'])
        stage['_manifest_sha256'] = plan['accepted_stage_manifest_sha256']
        accepted = load_private(plan['accepted_stage_receipt'], plan['accepted_stage_receipt_sha256'])
        require(accepted.get('status') == 'PROBE_AFTER_PASS' and accepted.get('completed_count') == 1
                and accepted['manifest_sha256'] == stage['_manifest_sha256']
                and stage['images'] == candidate['images'] and stage['config_digests'] == candidate['config_digests']
                and stage['nginx_sha256'] == candidate['nginx_sha256']
                and stage['configuration_commit'] == candidate['configuration_commit']
                and stage['adapter_sha256'] == candidate['adapter_sha256']
                and candidate['project'] not in (stage['project'], plan['application_uuid']))
        recent(accepted['checked_at'])
        require(candidate['configuration_commit'] == stage['configuration_commit'])
        if plan.get('rehearsal_receipt'):
            rehearsal = load_private(plan['rehearsal_receipt'], plan['rehearsal_receipt_sha256'])
            require(rehearsal.get('status') == 'RECOVERY_REHEARSAL_PASS'
                    and rehearsal.get('application_uuid') == plan['application_uuid']
                    and rehearsal.get('images') == candidate['images']
                    and rehearsal.get('configuration_commit') == candidate['configuration_commit']
                    and rehearsal.get('synthetic_recovery') == 'PASS')
            recent(rehearsal['checked_at'])
    require(set(plan.get('custom_plugins', [])) == set(plan['custom_plugins'])
            and set(plan.get('custom_themes', [])) == set(plan['custom_themes']))
    for name in plan['custom_plugins'] + plan['custom_themes'] + plan['operator_config_files']:
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name))
    require(not set(plan['operator_config_files']) & {'internal.php', 'version.php', 'config-defaults.php', 'routes.php'})
    plan.update(_plan_sha256=digest, _legacy=services, _source=source, _candidate=candidate)
    return plan


def provider_gate(plan):
    value = load_private(plan['provider_receipt'])
    require(value.get('application_uuid') == plan['application_uuid'] and value.get('auto_deploy') is False
            and value.get('running_deployments') == [] and value.get('queued_deployments') == []
            and value.get('background_writers_absent') is True)
    recent(value['checked_at'], 600)


def legacy_state(plan, running=True):
    ids = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + plan['application_uuid']).decode().split()
    require(set(ids) == {item['Id'] for item in plan['_legacy'].values()})
    actual = json.loads(docker('inspect', *ids))
    for item in actual:
        service = item['Config']['Labels']['com.docker.compose.service']; original = plan['_legacy'][service]
        require(item['Id'] == original['Id'] and item['Image'] == original['Image']
                and item['Mounts'] == original['Mounts'] and item['Config'] == original['Config']
                and set(item['NetworkSettings']['Networks']) == set(original['NetworkSettings']['Networks']))
        if running: require(item['State']['Running'] is True and item['State'].get('Health', {}).get('Status') == 'healthy')
    db = plan['_legacy']['db']
    require(not any(db['NetworkSettings']['Ports'].values()))
    for name, connection in db['NetworkSettings']['Networks'].items():
        network = json.loads(docker('network', 'inspect', connection['NetworkID']))[0]
        require(set(network.get('Containers', {})) <= set(ids))


def database(db_id, statement):
    return docker('exec', '-i', db_id, 'sh', '-eu', '-c',
                  'export MYSQL_PWD=$MARIADB_ROOT_PASSWORD; exec mariadb --batch --skip-column-names '
                  '--user=root "$MARIADB_DATABASE"', data=statement.encode()).decode().splitlines()


def config_metadata(app_id):
    code = '$c=include "application/config/config.php"; $s=include "application/config/security.php"; echo json_encode(["prefix"=>$c["components"]["db"]["tablePrefix"],"security"=>["encryptionnonce"=>!empty($s["encryptionnonce"]),"encryptionsecretboxkey"=>!empty($s["encryptionsecretboxkey"])]]);'
    result = json.loads(docker('exec', app_id, 'php', '-r', code))
    require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', result['prefix'])
            and result['security'] == {'encryptionnonce': True, 'encryptionsecretboxkey': True})
    return result


def db_inventory(db_id, prefix):
    require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', prefix))
    tables = database(db_id, 'SELECT TABLE_NAME,TABLE_TYPE,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME;')
    names = {}; counts = {}
    for line in tables:
        name, kind, engine = line.split('\t')
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) and kind == 'BASE TABLE' and engine in ('MyISAM', 'InnoDB'))
        names[name] = engine
        counts[name] = int(database(db_id, 'SELECT COUNT(*) FROM `' + name + '`;')[0])
    require(names and prefix + 'settings_global' in names)
    objects = database(db_id, 'SELECT (SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()),(SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE()),(SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=DATABASE());')
    require(objects == ['0\t0\t0'])
    schema = int(database(db_id, 'SELECT stg_value FROM `' + prefix + 'settings_global` WHERE stg_name="DBVersion";')[0])
    permissions = database(db_id, 'SELECT JSON_ARRAY(entity_id,entity,permission,uid,MAX(create_p),MAX(read_p),MAX(update_p),MAX(delete_p),MAX(import_p),MAX(export_p)) FROM `' + prefix + 'permissions` GROUP BY entity_id,entity,permission,uid ORDER BY entity_id,entity,permission,uid;')
    active = database(db_id, 'SELECT sid FROM `' + prefix + 'surveys` WHERE active="Y" ORDER BY sid;')
    require(all(re.fullmatch(r'[1-9][0-9]*', sid) for sid in active))
    return {'prefix': prefix, 'schema': schema, 'engines': names, 'counts': counts,
            'permissions': [json.loads(line) for line in permissions],
            'active_response_tables': [prefix + 'responses_' + sid for sid in active if prefix + 'responses_' + sid in names]}


def checkpoint(plan, state, status):
    state['status'] = status; state['checked_at'] = datetime.now(timezone.utc).isoformat()
    save_private(plan['state_file'], state)


def acknowledgement(plan, state, kind):
    path = Path(plan['directory']) / (kind + '.json')
    expected_state = file_hash(plan['state_file']); deadline = time.monotonic() + plan['ack_timeout']
    while not path.exists():
        require(time.monotonic() < deadline); time.sleep(1)
    value = load_private(path)
    require(value.get('transaction_id') == state['transaction_id'] and value.get('state_sha256') == expected_state)
    recent(value['checked_at'], 600)
    return value


def archive_inventory(path):
    result = {}
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            require(not name.startswith('/') and '..' not in Path(name).parts)
            require(not member.isdev() and not member.isfifo())
            if member.issym() or member.islnk():
                destination = posixpath.normpath(posixpath.join(posixpath.dirname(name) if member.issym() else '', member.linkname))
                require(not destination.startswith('/') and destination != '..' and not destination.startswith('../'))
                require(name not in result); result[name] = 'LINK:' + member.linkname
            if member.isfile():
                stream = archive.extractfile(member); digest = hashlib.sha256()
                while chunk := stream.read(1024 * 1024): digest.update(chunk)
                require(name not in result); result[name] = digest.hexdigest()
    require('application/config/config.php' in result and 'application/config/security.php' in result)
    return result


def paired_backup(plan, state):
    legacy_state(plan); metadata = config_metadata(plan['_legacy']['app']['Id'])
    db_id = plan['_legacy']['db']['Id']
    require(db_inventory(db_id, metadata['prefix'])['schema'] == 712)
    checkpoint(plan, state, 'WRITERS_FENCING')
    docker('stop', '-t', '30', plan['_legacy']['nginx']['Id'], plan['_legacy']['app']['Id'], timeout=90)
    stopped = json.loads(docker('inspect', plan['_legacy']['nginx']['Id'], plan['_legacy']['app']['Id']))
    require(len(stopped) == 2 and all(item['State']['Running'] is False for item in stopped))
    state['writers_fenced'] = True; checkpoint(plan, state, 'WRITERS_FENCED')
    # Re-read after writer quiescence. MyISAM consistency requires server table locks.
    inventory = db_inventory(db_id, metadata['prefix']); require(inventory['schema'] == 712)
    docker('exec', db_id, 'sh', '-eu', '-c',
           'umask 077; export MYSQL_PWD=$MARIADB_ROOT_PASSWORD; mariadb-dump --lock-all-tables --quick '
           '--routines --events --triggers --user=root "$MARIADB_DATABASE" > /tmp/limesurvey-paired.sql', timeout=300)
    directory = Path(plan['directory']); dump = directory / 'database.sql'; files = directory / 'files.tar.gz'
    docker('cp', db_id + ':/tmp/limesurvey-paired.sql', str(dump), timeout=300); dump.chmod(0o600)
    docker('exec', db_id, 'rm', '-f', '/tmp/limesurvey-paired.sql')
    owner = LABEL + '=' + plan['_plan_sha256']
    helper = docker('create', '--network', 'none', '--user', '0', '--label', owner,
                    '--volumes-from', plan['_legacy']['app']['Id'] + ':ro', '--entrypoint', 'sh',
                    plan['_legacy']['app']['Image'], '-eu', '-c',
                    'umask 077; tar -C /var/www/html -czf /tmp/limesurvey-paired-files.tar.gz .').decode().strip()
    require(re.fullmatch(r'[0-9a-f]{64}', helper)); state['archive_container'] = helper; checkpoint(plan, state, 'BACKUP_ARCHIVING')
    docker('start', '-a', helper, timeout=300)
    inspected = json.loads(docker('inspect', helper))[0]
    require(inspected['Id'] == helper and inspected['Config']['Labels'].get(LABEL) == plan['_plan_sha256']
            and inspected['State']['ExitCode'] == 0)
    docker('cp', helper + ':/tmp/limesurvey-paired-files.tar.gz', str(files), timeout=300); files.chmod(0o600)
    docker('rm', helper); state['archive_container'] = None
    hashes = {'database.sql': file_hash(dump), 'files.tar.gz': file_hash(files)}
    state['backup'] = {'sha256': hashes, 'inventory': inventory, 'files': archive_inventory(files),
                       'legacy_images': {name: item['Image'] for name, item in plan['_legacy'].items()},
                       'source_host_id': hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()}
    checkpoint(plan, state, 'BACKUP_READY')
    ack = acknowledgement(plan, state, 'offhost')
    require(ack.get('status') == 'OFFHOST_HASH_VERIFIED' and ack.get('sha256') == hashes
            and isinstance(ack.get('destination_host_id'), str) and re.fullmatch(r'[0-9a-f]{64}', ack['destination_host_id']) and ack['destination_host_id'] != state['backup']['source_host_id'])
    state['offhost'] = ack; checkpoint(plan, state, 'OFFHOST_VERIFIED')
    return state['backup']


def restore_paths(plan, inventory):
    selected = {'application/config/config.php', 'application/config/security.php'}
    if 'application/config/allowed_hosts.php' in inventory: selected.add('application/config/allowed_hosts.php')
    selected |= {'application/config/' + name for name in plan['operator_config_files']}
    roots = ['upload/'] + ['plugins/' + name + '/' for name in plan['custom_plugins']] + ['themes/' + name + '/' for name in plan['custom_themes']]
    selected |= {name for name in inventory if any(name.startswith(root) for root in roots)}
    require(selected <= inventory.keys())
    return selected


def filtered_archive(plan, backup):
    source = Path(plan['directory']) / 'files.tar.gz'; target = Path(plan['directory']) / ('restore-files-' + secrets.token_hex(8) + '.tar.gz')
    selected = restore_paths(plan, backup['files'])
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as output, tarfile.open(source, 'r:gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if name not in selected: continue
            require(member.isfile() and not member.issym() and not member.islnk())
            member.name = name; output.addfile(member, archive.extractfile(member))
    require(file_hash(source) == backup['sha256']['files.tar.gz'])
    return target, {name: backup['files'][name] for name in selected}


def selected_compose(plan, isolated):
    candidate = plan['_candidate']
    if isolated:
        # Use the exact admitted adapter, with copied private DB credentials only in process environment.
        existing = plan['_source']['services']['db']['environment']
        environment = dict(os.environ); environment.update(adapter_environment(candidate))
        for key in ('NAME', 'USER', 'PASSWORD', 'ROOT_PASSWORD'):
            source_key = 'MARIADB_DATABASE' if key == 'NAME' else 'MARIADB_' + key
            require(isinstance(existing.get(source_key), str) and existing[source_key])
            environment['STAGING_DB_' + key] = existing[source_key]
        source = json.loads(command(['docker', 'compose', '--project-directory', candidate['repository_root'],
                                     '--project-name', candidate['project'], '--file', str(ROOT / 'deploy/staging.compose.yaml'),
                                     'config', '--format', 'json'], env=environment, timeout=30))
        canonical = Path(candidate['repository_root']) / 'docker/nginx/default.conf'
        require(file_hash(canonical) == candidate['nginx_sha256'] and source['name'] == candidate['project'])
        binds = [mount for mount in source['services']['nginx']['volumes'] if mount['type'] == 'bind']
        require(len(binds) == 1 and binds[0]['source'] == str(canonical)
                and binds[0]['target'] == '/etc/nginx/conf.d/default.conf' and binds[0]['read_only'] is True)
        for definition in source['services'].values():
            definition['labels'] = {LABEL: candidate['_manifest_sha256']}
            definition['pull_policy'] = 'never'
            definition.get('environment', {}).pop('YII_CONSOLE_COMMANDS', None)
        return source
    source = copy.deepcopy(plan['_source'])
    source['name'] = candidate['project'] if isolated else plan['application_uuid']
    for service, definition in source['services'].items():
        definition.pop('build', None); definition.pop('container_name', None)
        definition['image'] = candidate['images'][IMAGES[service]]; definition['platform'] = 'linux/arm64'
        definition['pull_policy'] = 'never'
        if isolated:
            definition['labels'] = {LABEL: candidate['_manifest_sha256']}
            definition['networks'] = {'backend': {}} if service != 'nginx' else {'backend': {}, 'frontend': {}}
            definition.pop('ports', None)
            if service == 'nginx': definition['ports'] = [{'target': 80, 'published': str(candidate['port']), 'host_ip': '127.0.0.1', 'protocol': 'tcp'}]
        environment = definition.get('environment', {})
        environment.pop('YII_CONSOLE_COMMANDS', None)
        require(isinstance(environment, dict))
        if service != 'app':
            definition['environment'] = {name: value for name, value in environment.items() if not name.startswith('RESEND_')}
        elif isolated: environment['RESEND_API_KEY'] = ''
        for mount in definition['volumes']:
            if mount['type'] == 'volume':
                matches = [name for name, target in VOLUMES.items() if target == mount['target']]
                require(len(matches) == 1); mount['source'] = candidate['volumes'][matches[0]]
            elif mount['type'] == 'bind':
                require(service == 'nginx' and mount['target'] == '/etc/nginx/conf.d/default.conf')
                mount['source'] = str(Path(candidate['repository_root']) / 'docker/nginx/default.conf'); mount['read_only'] = True
            else: require(mount['type'] == 'tmpfs')
    source['volumes'] = {name: {'external': True, 'name': name} for name in candidate['volumes'].values()}
    if isolated: source['networks'] = {name: {'external': True, 'name': actual} for name, actual in candidate['networks'].items()}
    else:
        for name, definition in source['networks'].items():
            require(isinstance(definition.get('name'), str)); source['networks'][name] = {'external': True, 'name': definition['name']}
    return source


def compose(path, project, *arguments, timeout=180):
    return docker('compose', '--project-name', project, '--file', str(path), *arguments, timeout=timeout)


def project_container(project, service):
    ids = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project,
                 '--filter', 'label=com.docker.compose.service=' + service).decode().split()
    require(len(ids) == 1); return ids[0]


def wait_db(project):
    deadline = time.monotonic() + 180
    while True:
        identifier = project_container(project, 'db')
        inspected = json.loads(docker('inspect', identifier))[0]
        if inspected['State'].get('Health', {}).get('Status') == 'healthy': return identifier
        require(time.monotonic() < deadline); time.sleep(2)


def wait_runtime(candidate, state):
    deadline = time.monotonic() + 180
    while True:
        try: return runtime(candidate, state)
        except GateError:
            require(time.monotonic() < deadline); time.sleep(2)


def candidate_database(plan, db_id):
    candidate = plan['_candidate']; state = load_private(candidate['state_file'])
    owned_resources(candidate, state)
    item = json.loads(docker('inspect', db_id))[0]
    inspected_images = json.loads(docker('image', 'inspect', candidate['images']['mariadb']))
    image_identity(candidate, 'mariadb', inspected_images)
    image = inspected_images[0]
    require(item['Id'] == db_id and item['Image'] == image['Id']
            and item['Config']['Image'] == candidate['images']['mariadb']
            and item['Config']['Labels']['com.docker.compose.project'] == candidate['project']
            and item['Config']['Labels']['com.docker.compose.service'] == 'db'
            and item['State']['Running'] is True and item['State'].get('Health', {}).get('Status') == 'healthy')
    mounts = item['Mounts']; require(len(mounts) == 1)
    require(mounts[0]['Type'] == 'volume' and mounts[0]['Name'] == candidate['volumes']['db']
            and mounts[0]['Destination'] == '/var/lib/mysql' and mounts[0]['RW'] is True)
    runtime_options('db', item, image)
    networks = item['NetworkSettings']['Networks']; name = candidate['networks']['backend']
    require(set(networks) == {name} and networks[name]['NetworkID'] == state['resources'][name]['id']
            and not any(item['NetworkSettings']['Ports'].values())
            and not item['HostConfig'].get('Privileged', False) and not item['HostConfig'].get('CapAdd')
            and not item['HostConfig'].get('Devices') and item['HostConfig'].get('PidMode', '') == '')


def import_database(db_id, plan, backup, reset=False):
    candidate_database(plan, db_id)
    dump = Path(plan['directory']) / 'database.sql'
    require(file_hash(dump) == backup['sha256']['database.sql'])
    if reset:
        # This is called only for the fresh isolated candidate, never the legacy database.
        name = database(db_id, 'SELECT DATABASE();')[0]; require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name))
        database(db_id, 'DROP DATABASE `' + name + '`; CREATE DATABASE `' + name + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;')
    else: require(database(db_id, 'SHOW TABLES;') == [])
    docker('cp', str(dump), db_id + ':/tmp/limesurvey-restore.sql', timeout=300)
    docker('exec', db_id, 'sh', '-eu', '-c', 'export MYSQL_PWD=$MARIADB_ROOT_PASSWORD; '
           'mariadb --user=root "$MARIADB_DATABASE" < /tmp/limesurvey-restore.sql', timeout=300)
    docker('exec', db_id, 'rm', '-f', '/tmp/limesurvey-restore.sql')
    require(db_inventory(db_id, backup['inventory']['prefix']) == backup['inventory'])


def restore_files(plan, backup, project, repeated=False):
    archive, selected = filtered_archive(plan, backup)
    candidate = plan['_candidate']; mounts = []
    for kind in ('code', 'config', 'upload', 'plugins', 'themes', 'runtime'):
        mounts += ['--mount', 'type=volume,src=' + candidate['volumes'][kind] + ',dst=' + VOLUMES[kind]]
    mounts += ['--mount', 'type=bind,src=' + str(archive) + ',dst=/restore-files.tar.gz,readonly']
    # Refuse a custom directory that would overlay an image-provided default.
    guards = ['test ! -e /var/www/html/plugins/' + name for name in plan['custom_plugins']]
    guards += ['test ! -e /var/www/html/themes/' + name for name in plan['custom_themes']]
    if repeated: guards = []
    inventory_file = Path(plan['directory']) / ('restore-inventory-' + secrets.token_hex(8) + '.json')
    save_private(inventory_file, selected)
    mounts += ['--mount', 'type=bind,src=' + str(inventory_file) + ',dst=/restore-inventory.json,readonly']
    verifier = 'foreach(json_decode(file_get_contents("/restore-inventory.json"),true) as $p=>$h){if(hash_file("sha256","/var/www/html/".$p)!==$h){exit(1);}}'
    script = '; '.join(guards + ['tar -C /var/www/html -xzf /restore-files.tar.gz', 'chown -R www-data:www-data /var/www/html/application/config /var/www/html/upload /var/www/html/plugins /var/www/html/themes /var/www/html/tmp', "php -r '" + verifier + "'"])
    helper = docker('create', '--network', 'none', '--user', '0', '--label', LABEL + '=' + plan['_plan_sha256'],
                    '--entrypoint', 'sh', *mounts, candidate['images']['php'], '-eu', '-c', script).decode().strip()
    require(re.fullmatch(r'[0-9a-f]{64}', helper)); docker('start', '-a', helper, timeout=180)
    inspected = json.loads(docker('inspect', helper))[0]
    require(inspected['Id'] == helper and inspected['Config']['Labels'].get(LABEL) == plan['_plan_sha256']
            and inspected['Config']['Image'] == candidate['images']['php'] and inspected['State']['ExitCode'] == 0)
    docker('rm', helper)
    # Every selected regular file, including the original encryption identity, must survive.
    return selected


def migration_postconditions(db_id, before):
    prefix = before['prefix']; after = db_inventory(db_id, prefix)
    require(after['schema'] == 717 and after['permissions'] == before['permissions'])
    for table, count in before['counts'].items():
        if table in before['active_response_tables'] or table in (prefix + 'surveys', prefix + 'users', prefix + 'plugins'):
            require(after['counts'].get(table) == count)
    for table in before['active_response_tables']:
        require(database(db_id, 'SELECT COLUMN_TYPE,IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME="' + table + '" AND COLUMN_NAME="quota_exit";') == ['int(11)\tYES'])
    for table in (prefix + 'surveys', prefix + 'surveys_groupsettings'):
        require(database(db_id, 'SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME="' + table + '" AND COLUMN_NAME="savequotaexit";') == ['1'])
    require(database(db_id, 'SELECT COLUMN_TYPE,IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME="' + prefix + 'users" AND COLUMN_NAME="session_token";') == ['varchar(64)\tYES'])
    require(database(db_id, 'SELECT COUNT(*) FROM `' + prefix + 'plugins` WHERE plugin_type IS NULL;') == ['0'])
    require(database(db_id, 'SELECT COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME="' + prefix + 'surveys" AND COLUMN_NAME="savequotaexit";') in (["'N'"], ['N']))
    require(database(db_id, 'SELECT COUNT(*) FROM `' + prefix + 'surveys_groupsettings` WHERE gsid <> 0 AND savequotaexit <> "I";') == ['0'])
    require(database(db_id, 'SELECT COUNT(*) FROM `' + prefix + 'template_configuration` WHERE template_name="fruity_twentythree" AND options<>"inherit" AND options NOT LIKE "%deselectsinglechoice%";') == ['0'])
    index = database(db_id, 'SELECT COLUMN_NAME,NON_UNIQUE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME="' + prefix + 'permissions" AND INDEX_NAME="idx1_permissions" ORDER BY SEQ_IN_INDEX;')
    require(index == ['entity_id\t0', 'entity\t0', 'permission\t0', 'uid\t0'])
    # Template XML/DB interpretation and actual render are additionally checked by the controller.
    return after


def migrate_candidate(plan, state, db_id, compose_file, recovery=False):
    backup = state['backup']; candidate_database(plan, db_id)
    require(db_inventory(db_id, backup['inventory']['prefix'])['schema'] == 712)
    name = plan['_candidate']['project'] + '-migration-' + state['transaction_id'] + ('-recovery' if recovery else '')
    require(not docker('ps', '-aq', '--filter', 'name=^/' + name + '$').strip())
    log = Path(plan['directory']) / ('recovery-migration.private.log' if recovery else 'migration.private.log')
    descriptor = os.open(log, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    checkpoint(plan, state, 'MIGRATION_RUNNING')
    identifier = None
    try:
        source = load_private(compose_file); migration = copy.deepcopy(source['services']['app'])
        migration.pop('depends_on', None); migration.pop('profiles', None); migration.pop('ports', None)
        migration.update(container_name=name, user='www-data', entrypoint=['php'],
                         command=['application/commands/console.php', 'updatedb'], restart='no',
                         labels={LABEL: plan['_plan_sha256']})
        migration.get('environment', {}).pop('YII_CONSOLE_COMMANDS', None)
        source.update(name=name, services={'migration': migration})
        migration_file = Path(plan['directory']) / ('recovery-updater.compose.private.json' if recovery else 'updater.compose.private.json')
        save_private(migration_file, source)
        compose(migration_file, name, 'create', '--no-build', '--pull', 'never', 'migration')
        identifier = project_container(name, 'migration')
        require(re.fullmatch(r'[0-9a-f]{64}', identifier))
        item = json.loads(docker('inspect', identifier))[0]
        require(item['Id'] == identifier and item['Name'] == '/' + name
                and item['Config']['Labels'].get(LABEL) == plan['_plan_sha256']
                and item['Config']['Image'] == plan['_candidate']['images']['php']
                and item['State']['Running'] is False)
        expected_mounts = {key: plan['_candidate']['volumes'][key] for key in set(VOLUMES) - {'db'}}
        mounts = item['Mounts']; require(len(mounts) == len(expected_mounts))
        for key, volume in expected_mounts.items():
            require(any(mount['Type'] == 'volume' and mount['Name'] == volume
                        and mount['Destination'] == VOLUMES[key] and mount['RW'] is True for mount in mounts))
        state['migration_container'] = identifier; checkpoint(plan, state, 'MIGRATION_RUNNING')
        docker('start', identifier)
        require(docker('wait', identifier, timeout=300).strip() == b'0')
        state['migration'] = migration_postconditions(db_id, backup['inventory'])
        checkpoint(plan, state, 'MIGRATION_VERIFIED')
    except Exception:
        if identifier and state.get('migration_container') == identifier:
            docker('stop', '-t', '10', identifier, timeout=30)
            item = json.loads(docker('inspect', identifier))[0]
            require(item['Id'] == identifier and item['Config']['Labels'].get(LABEL) == plan['_plan_sha256']
                    and item['State']['Running'] is False)
        raise
    finally:
        with os.fdopen(descriptor, 'wb') as stream:
            if identifier and state.get('migration_container') == identifier:
                subprocess.run(['docker', 'logs', identifier], stdout=stream, stderr=stream, timeout=30, check=False)
    # Retain the stopped owned one-off and protected log as migration evidence.


def legacy_rescue(plan, state):
    # Rescue reattaches only retained original volumes after proving the original pair.
    require(state.get('public_unfenced') is not True)
    require(state.get('plan_sha256') == plan['_plan_sha256']
            and state.get('application_uuid') == plan['application_uuid']
            and state.get('backup') and state.get('offhost') and state['backup']['inventory']['schema'] == 712)
    for name, expected in state['backup']['sha256'].items(): require(file_hash(Path(plan['directory']) / name) == expected)
    legacy = copy.deepcopy(plan['_source']); legacy['name'] = plan['application_uuid']
    for service, definition in legacy['services'].items():
        definition.pop('build', None); definition.pop('container_name', None)
        definition['image'] = plan['_legacy'][service]['Image']; definition['pull_policy'] = 'never'
    target = Path(plan['directory']) / 'legacy-rescue.compose.private.json'; save_private(target, legacy)
    # Reject an unrelated workload before stopping anything under the selected UUID.
    identifiers = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + plan['application_uuid']).decode().split()
    if identifiers:
        current = json.loads(docker('inspect', *identifiers))
        require(len(current) == 3)
        resolved = {kind: json.loads(docker('image', 'inspect', reference))[0]['Id']
                    for kind, reference in plan['_candidate']['images'].items()}
        for item in current:
            service = item['Config']['Labels']['com.docker.compose.service']
            require(service in IMAGES and item['Image'] in (plan['_legacy'][service]['Image'], resolved[IMAGES[service]]))
        docker('stop', '-t', '30', *[item['Id'] for item in current if item['Config']['Labels']['com.docker.compose.service'] != 'db'], timeout=90)
    state['writers_fenced'] = True; checkpoint(plan, state, 'LEGACY_RESCUE_FENCED')
    try:
        compose(target, plan['application_uuid'], 'up', '-d', '--no-build', '--pull', 'never', 'db', timeout=300)
        db_id = wait_db(plan['application_uuid'])
        inspected = json.loads(docker('inspect', db_id))[0]
        original_db = plan['_legacy']['db']
        require(inspected['Image'] == original_db['Image'] and inspected['Mounts'] == original_db['Mounts'])
        require(db_inventory(db_id, state['backup']['inventory']['prefix']) == state['backup']['inventory'])
        expected = {name: state['backup']['files'][name] for name in restore_paths(plan, state['backup']['files'])}
        payload = base64.b64encode(json.dumps(expected).encode()).decode()
        code = 'foreach(json_decode(base64_decode("' + payload + '"),true) as $p=>$h){if(hash_file("sha256","/var/www/html/".$p)!==$h){exit(1);}}'
        compose(target, plan['application_uuid'], 'run', '--rm', '--no-deps', '--user', 'www-data', '--entrypoint', 'php', 'app', '-r', code)
        compose(target, plan['application_uuid'], 'up', '-d', '--no-build', '--pull', 'never', timeout=300)
        checkpoint(plan, state, 'LEGACY_RESCUE_READY')
        proof = acknowledgement(plan, state, 'legacy-proof')
        require(proof.get('status') == 'LEGACY_RESCUE_FUNCTIONAL_PASS'
                and proof.get('admin') == proof.get('public') == proof.get('persistence') == 'PASS'
                and proof.get('security_sha256') == expected['application/config/security.php'])
        state['legacy_proof'] = proof; state['writers_fenced'] = False
        checkpoint(plan, state, 'LEGACY_RESCUE_RUNNING')
        return {'status': 'LEGACY_RESCUE_RUNNING', 'security': 'LEGACY_INELIGIBLE', 'mail_delivery': 'UNKNOWN'}
    except Exception:
        compose(target, plan['application_uuid'], 'stop', 'app', 'nginx')
        checkpoint(plan, state, 'LEGACY_RESCUE_FAILED_PRESERVED')
        raise


def production_runtime(plan, state, fenced=True):
    candidate = plan['_candidate']; candidate_state = load_private(candidate['state_file'])
    owned_resources(candidate, candidate_state)
    identifiers = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + plan['application_uuid']).decode().split()
    require(len(identifiers) == 3)
    actual = json.loads(docker('inspect', *identifiers)); result = {}
    for item in actual:
        service = item['Config']['Labels']['com.docker.compose.service']; require(service in IMAGES and service not in result)
        kind = IMAGES[service]; reference = candidate['images'][kind]
        inspected_images = json.loads(docker('image', 'inspect', reference))
        image_identity(candidate, kind, inspected_images); image = inspected_images[0]
        require(item['Image'] == image['Id'] and item['Config']['Image'] == reference
                and item['Config']['Labels']['com.docker.compose.project'] == plan['application_uuid']
                and item['State']['Running'] is True and item['State'].get('Health', {}).get('Status') == 'healthy')
        expected = set(VOLUMES) - {'db'} if service == 'app' else ({'db'} if service == 'db' else {'code', 'upload', 'plugins', 'themes', 'runtime'})
        mounts = [mount for mount in item['Mounts'] if mount['Type'] == 'volume']; require(len(mounts) == len(expected))
        for name in expected:
            matches = [mount for mount in mounts if mount['Destination'] == VOLUMES[name]]
            require(len(matches) == 1 and matches[0]['Name'] == candidate['volumes'][name] and matches[0]['RW'] is (service != 'nginx'))
        require(set(item['NetworkSettings']['Networks']) == set(plan['_legacy'][service]['NetworkSettings']['Networks']))
        require(not item['HostConfig'].get('Privileged', False) and not item['HostConfig'].get('CapAdd')
                and not item['HostConfig'].get('Devices') and item['HostConfig'].get('PidMode', '') == '')
        if service == 'db':
            require(not any(item['NetworkSettings']['Ports'].values()))
            for connection in item['NetworkSettings']['Networks'].values():
                network = json.loads(docker('network', 'inspect', connection['NetworkID']))[0]
                require(network.get('Internal') is True and set(network.get('Containers', {})) <= set(identifiers))
        if service == 'nginx':
            binds = [mount for mount in item['Mounts'] if mount['Type'] == 'bind']
            expected_file = str(Path(plan['directory']) / 'nginx-fenced.private.conf') if fenced else str(Path(candidate['repository_root']) / 'docker/nginx/default.conf')
            require(len(binds) == 1 and binds[0]['Source'] == expected_file
                    and binds[0]['Destination'] == '/etc/nginx/conf.d/default.conf' and binds[0]['RW'] is False)
            raw = docker('exec', item['Id'], 'cat', '/etc/nginx/conf.d/default.conf')
            require(hashlib.sha256(raw).hexdigest() == (state['fence_config_sha256'] if fenced else candidate['nginx_sha256']))
            docker('exec', item['Id'], 'nginx', '-t')
        else: require(not any(mount['Type'] == 'bind' for mount in item['Mounts']))
        result[service] = {'id': item['Id'], 'image_id': item['Image'], 'reference': reference}
    require(set(result) == set(IMAGES)); return result


def wait_production(plan, state, fenced=True):
    deadline = time.monotonic() + 180
    while True:
        try: return production_runtime(plan, state, fenced)
        except GateError:
            require(time.monotonic() < deadline); time.sleep(2)


def fenced_compose(plan, state):
    candidate = plan['_candidate']
    canonical = Path(candidate['repository_root']) / 'docker/nginx/default.conf'
    raw = canonical.read_text(); require(file_hash(canonical) == candidate['nginx_sha256'])
    require(len(re.findall(r'\bserver\s*\{', raw)) == 1)
    token = secrets.token_hex(32)
    require(re.search(r'location\s*=\s*/healthz\s*\{', raw))
    maps = 'map $http_x_limesurvey_delivery_token $delivery_authorized { default 0; "' + token + '" 1; }\n'
    maps += 'map "$delivery_authorized:$uri" $delivery_allowed { default 0; ~^1: 1; "0:/healthz" 1; }\n'
    config = maps + re.sub(r'(\bserver\s*\{)', lambda match: match[0] + '\n    if ($delivery_allowed = 0) { return 503; }', raw, count=1)
    path = Path(plan['directory']) / 'nginx-fenced.private.conf'
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as stream: stream.write(config)
    token_file = Path(plan['directory']) / 'fence-token.private.json'; save_private(token_file, {'token': token})
    state['fence_token_file'] = str(token_file); state['fence_config_sha256'] = file_hash(path)
    result = selected_compose(plan, False)
    binds = [mount for mount in result['services']['nginx']['volumes'] if mount['type'] == 'bind']
    require(len(binds) == 1); binds[0]['source'] = str(path)
    return result


def recovery_transaction(plan, rehearse=False):
    if not rehearse: require(plan.get('rehearsal_receipt') and plan.get('rehearsal_receipt_sha256'))
    directory = Path(plan['directory']); require(not directory.exists() and not Path(plan['state_file']).exists())
    directory.mkdir(mode=0o700)
    state = {'schema_version': 1, 'transaction_id': secrets.token_hex(16), 'plan_sha256': plan['_plan_sha256'],
             'application_uuid': plan['application_uuid'], 'writers_fenced': False, 'started_at': datetime.now(timezone.utc).isoformat()}
    checkpoint(plan, state, 'PREFLIGHT'); provider_gate(plan)
    try:
        backup = paired_backup(plan, state)
        if rehearse:
            docker('start', plan['_legacy']['app']['Id'], plan['_legacy']['nginx']['Id'])
            state['writers_fenced'] = False; checkpoint(plan, state, 'ORIGINAL_TRAFFIC_RESUMED')
        candidate = plan['_candidate']; prepare(candidate)
        restore = Path(plan['directory']) / 'restore.compose.private.json'; save_private(restore, selected_compose(plan, True))
        compose(restore, candidate['project'], 'up', '-d', '--no-build', '--pull', 'never', 'db')
        db_id = wait_db(candidate['project']); import_database(db_id, plan, backup)
        selected = restore_files(plan, backup, candidate['project']); state['restored_files'] = selected
        migrate_candidate(plan, state, db_id, restore)
        compose(restore, candidate['project'], 'up', '-d', '--no-build', '--pull', 'never')
        candidate_state = load_private(candidate['state_file']); candidate_state['status'] = 'INITIALIZED'
        candidate_state['database_prefix'] = backup['inventory']['prefix']
        candidate_state['containers'] = wait_runtime(candidate, candidate_state)
        save_private(candidate['state_file'], candidate_state)
        checkpoint(plan, state, 'RESTORE_READY')
        ack = acknowledgement(plan, state, 'restore-proof')
        require(ack.get('status') == 'RESTORE_FUNCTIONAL_PASS' and ack.get('admin') == ack.get('public') == ack.get('persistence') == 'PASS'
                and ack.get('security_sha256') == selected['application/config/security.php']
                and ack.get('default_theme_options') == 'PASS')
        state['restore_proof'] = ack; checkpoint(plan, state, 'RESTORE_FUNCTIONAL_VERIFIED')
        if rehearse:
            # Fault only the fresh isolated copy, then restore its matched 712 DB/files pair.
            compose(restore, candidate['project'], 'stop', 'app', 'nginx')
            fault = 'file_put_contents("application/config/config.php", "<?php this is a synthetic invalid configuration;");'
            compose(restore, candidate['project'], 'run', '--rm', '--no-deps', '--user', 'www-data', '--entrypoint', 'php', 'app', '-r', fault)
            failed = False
            try: compose(restore, candidate['project'], 'run', '--rm', '--no-deps', '--entrypoint', 'php', 'app', '-l', 'application/config/config.php')
            except GateError: failed = True
            require(failed)
            checkpoint(plan, state, 'SYNTHETIC_CONFIG_FAILURE_VERIFIED')
            import_database(db_id, plan, backup, reset=True)
            require(restore_files(plan, backup, candidate['project'], repeated=True) == selected)
            checkpoint(plan, state, 'PAIRED_712_RESTORE_VERIFIED')
            migrate_candidate(plan, state, db_id, restore, recovery=True)
            compose(restore, candidate['project'], 'up', '-d', '--no-build', '--pull', 'never')
            require(wait_runtime(candidate, candidate_state) == candidate_state['containers'])
            checkpoint(plan, state, 'RECOVERY_READY')
            recovered = acknowledgement(plan, state, 'recovery-proof')
            require(recovered.get('status') == 'RESTORE_FUNCTIONAL_PASS'
                    and recovered.get('admin') == recovered.get('public') == recovered.get('persistence') == 'PASS'
                    and recovered.get('security_sha256') == selected['application/config/security.php']
                    and recovered.get('default_theme_options') == 'PASS')
            state.update(synthetic_recovery='PASS', recovery_proof=recovered,
                         images=candidate['images'], configuration_commit=candidate['configuration_commit'])
            state['elapsed_seconds'] = (datetime.now(timezone.utc) - datetime.fromisoformat(state['started_at'])).total_seconds()
            checkpoint(plan, state, 'RECOVERY_REHEARSAL_PASS')
            return {'status': 'RECOVERY_REHEARSAL_PASS', 'mail_delivery': 'UNKNOWN'}
        manifest(Path(plan['candidate_manifest']), plan['candidate_manifest_sha256'])
        provider_gate(plan)
        compose(restore, candidate['project'], 'stop', timeout=180)
        production = Path(plan['directory']) / 'production.compose.private.json'; save_private(production, fenced_compose(plan, state))
        compose(production, plan['application_uuid'], 'up', '-d', '--no-build', '--pull', 'never', timeout=300)
        state['production_containers'] = wait_production(plan, state)
        checkpoint(plan, state, 'PRODUCTION_READY')
        ack = acknowledgement(plan, state, 'production-proof')
        require(ack.get('status') == 'PRODUCTION_CORE_PASS' and ack.get('https') == ack.get('admin') == ack.get('public') == ack.get('persistence') == 'PASS'
                and ack.get('ordinary_requests_fenced') == 'PASS'
                and ack.get('images') == candidate['images'] and ack.get('security_sha256') == selected['application/config/security.php'])
        require(ack.get('mail_delivery', 'UNKNOWN') in ('PASS', 'UNKNOWN'))
        state['production_proof'] = ack
        # Mark potential publication before removing the barrier. Never discard new writes via legacy rescue.
        state['public_unfenced'] = True; checkpoint(plan, state, 'PUBLIC_UNFENCING')
        save_private(production, selected_compose(plan, False))
        compose(production, plan['application_uuid'], 'up', '-d', '--no-build', '--pull', 'never', 'nginx', timeout=180)
        state['public_containers'] = wait_production(plan, state, fenced=False)
        checkpoint(plan, state, 'PUBLIC_READY')
        opened = acknowledgement(plan, state, 'production-open-proof')
        require(opened.get('status') == 'PUBLIC_HEALTH_PASS' and opened.get('https') == 'PASS')
        state['public_proof'] = opened; state['writers_fenced'] = False
        state['elapsed_seconds'] = (datetime.now(timezone.utc) - datetime.fromisoformat(state['started_at'])).total_seconds()
        checkpoint(plan, state, 'PROMOTED_CORE_VERIFIED')
        return {'status': 'PROMOTED_CORE_VERIFIED', 'mail_delivery': ack.get('mail_delivery', 'UNKNOWN')}
    except Exception:
        # Preserve the failed DB/files and close both ordinary and token-authorized writers.
        production_path = directory / 'production.compose.private.json'
        restore_path = directory / 'restore.compose.private.json'
        state['fence_stop_verified'] = False
        try:
            if production_path.exists(): compose(production_path, plan['application_uuid'], 'stop', 'app', 'nginx')
            if restore_path.exists(): compose(restore_path, plan['_candidate']['project'], 'stop', 'app', 'nginx')
            state['fence_stop_verified'] = True
        except Exception: pass
        checkpoint(plan, state, 'FAILED_PRESERVED')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('snapshot', 'stage', 'probe', 'cleanup-stage', 'rehearse', 'promote', 'legacy-rescue'))
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--plan', type=Path); parser.add_argument('--plan-sha256')
    parser.add_argument('--action', choices=('prepare', 'initialize', 'restart'))
    parser.add_argument('--phase', choices=('before', 'after'))
    parser.add_argument('--url'); parser.add_argument('--credentials', type=Path)
    parser.add_argument('--receipt', type=Path); parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--snapshot-sha256')
    args = parser.parse_args()
    try:
        if args.command in ('rehearse', 'promote', 'legacy-rescue'):
            require(args.plan and args.plan_sha256)
            plan = recovery_plan(args.plan, args.plan_sha256, rescue=args.command == 'legacy-rescue')
            with production_lock(plan['application_uuid']):
                result = legacy_rescue(plan, load_private(plan['state_file'])) if args.command == 'legacy-rescue' else recovery_transaction(plan, rehearse=args.command == 'rehearse')
            print(json.dumps(result, indent=2)); return 0
        require(args.manifest and args.manifest_sha256)
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
