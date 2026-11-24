#!/usr/bin/env python3
"""Local-only schema-717 paired transfer. No SSH, deployment or publication."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

SPEC = importlib.util.spec_from_file_location('crosshost_primitives', Path(__file__).with_name('operate.py'))
op = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(op)
require = op.require
LABEL = 'io.omnestack.limesurvey.crosshost'
HEX = r'[0-9a-f]{64}'
KINDS = ('config', 'upload', 'plugins', 'themes', 'runtime')


def private_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
    return path


def host_id():
    return hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()


def load_plan(path, digest):
    require(re.fullmatch(HEX, digest or '') is not None)
    plan = op.load_private(path, digest)
    require(plan.get('version') == 1 and plan.get('schema') == 717)
    require(re.fullmatch(r'[a-z0-9]{16,48}', plan.get('transaction', '')) is not None)
    require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', plan.get('prefix', '')) is not None)
    require(set(plan.get('hosts', {})) == {'source', 'target'})
    require(all(re.fullmatch(HEX, value) for value in plan['hosts'].values()))
    require(plan['hosts']['source'] != plan['hosts']['target'])
    private_directory(plan['directory'])
    for role in ('source', 'target'):
        side = plan[role]
        require(set(side['containers']) == {'app', 'nginx', 'db'})
        require(len({item['id'] for item in side['containers'].values()}) == 3)
        require(Path(side['nginx_config']['path']).is_absolute() and re.fullmatch(HEX, side['nginx_config']['sha256']))
        require(set(side['volumes']) == set(op.VOLUMES))
        require(len(set(side['volumes'].values())) == len(op.VOLUMES))
        require(all(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', name) for name in side['volumes'].values()))
        for item in side['containers'].values():
            require(re.fullmatch(HEX, item['id']) and re.fullmatch('sha256:' + HEX, item['image_id']))
            require(re.fullmatch(r'[^\s@]+@sha256:' + HEX, item['image']))
            require(item['networks'] and len(set(item['networks'])) == len(item['networks']))
            require(all(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', name) for name in item['networks']))
    require(set(plan['source']['volumes'].values()).isdisjoint(plan['target']['volumes'].values()))
    source_networks = {name for item in plan['source']['containers'].values() for name in item['networks']}
    target_networks = {name for item in plan['target']['containers'].values() for name in item['networks']}
    require(source_networks.isdisjoint(target_networks))
    require({item['id'] for item in plan['source']['containers'].values()}.isdisjoint(item['id'] for item in plan['target']['containers'].values()))
    for key in ('plugins', 'themes'):
        require(isinstance(plan['custom_' + key], list))
        require(all(re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', name) for name in plan['custom_' + key]))
        require(len(set(plan['custom_' + key])) == len(plan['custom_' + key]))
    plan['_sha256'] = digest
    return plan


@contextmanager
def locked(plan):
    path = Path(plan['directory']) / 'transaction.lock'
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        require(stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def inspect_side(plan, role, stopped=False):
    require(host_id() == plan['hosts'][role])
    side = plan[role]
    result = {}
    nginx_config = Path(side['nginx_config']['path'])
    require(nginx_config.resolve() == nginx_config and nginx_config.is_file() and op.file_hash(nginx_config) == side['nginx_config']['sha256'])
    for service, expected in side['containers'].items():
        actual = json.loads(op.docker('inspect', expected['id']))[0]
        require(actual['Id'] == expected['id'] and actual['Image'] == expected['image_id']
                and actual['Config']['Image'] == expected['image'])
        require(set(actual['NetworkSettings']['Networks']) == set(expected['networks']))
        require(actual['HostConfig'].get('NetworkMode') != 'host'
                and not actual['HostConfig'].get('Privileged'))
        volumes = {mount['Destination']: mount for mount in actual['Mounts'] if mount['Type'] == 'volume'}
        required = ('db',) if service == 'db' else tuple(op.VOLUMES)[1:] if service == 'app' else ('code', 'upload', 'plugins', 'themes', 'runtime')
        require(set(volumes) == {op.VOLUMES[kind] for kind in required})
        for kind in required:
            mount = volumes[op.VOLUMES[kind]]
            require(mount['Name'] == side['volumes'][kind] and mount['RW'] is (service != 'nginx'))
        binds = [m for m in actual['Mounts'] if m['Type'] == 'bind']
        require(not binds if service != 'nginx' else len(binds) == 1 and binds[0]['Destination'] == '/etc/nginx/conf.d/default.conf' and not binds[0]['RW'] and binds[0]['Source'] == str(nginx_config))
        if service == 'db' or (role == 'target' and service == 'app'):
            require(not actual['HostConfig'].get('PortBindings')
                    and not actual['HostConfig'].get('PublishAllPorts')
                    and not any(actual['NetworkSettings'].get('Ports', {}).values()))
        if role == 'target':
            ports = actual['HostConfig'].get('PortBindings') or {}
            require(not ports if service != 'nginx' else set(ports) <= {'80/tcp'} and all(binding['HostIp'] == '127.0.0.1' for bindings in ports.values() for binding in bindings))
            require(not any(name.startswith(('traefik.', 'caddy')) for name in (actual['Config'].get('Labels') or {})))
        require(actual['State']['Running'] is (service == 'db' or not stopped))
        result[service] = actual
    # Reject an unlisted container sharing writable volumes (including stopped
    # containers which an external supervisor might restart).
    ids = op.docker('ps', '-aq', '--no-trunc').decode().split()
    if ids:
        owned = {item['id'] for item in side['containers'].values()}
        for item in json.loads(op.docker('inspect', *ids)):
            if item['Id'] not in owned:
                require(not any(m.get('RW') and m.get('Name') in side['volumes'].values() for m in item.get('Mounts', [])))
    if role == 'source':
        # A published DB or an extra network client could write while HTTP/FPM
        # are fenced. Require the reviewed app+DB-only internal bridge.
        networks = side['containers']['db']['networks']
        require(len(networks) == 1 and networks[0] in side['containers']['app']['networks']
                and networks[0] not in side['containers']['nginx']['networks'])
        network = json.loads(op.docker('network', 'inspect', networks[0]))[0]
        db_id = side['containers']['db']['id']; app_id = side['containers']['app']['id']
        clients = set(network.get('Containers', {}))
        require(network['Name'] == networks[0] and network['Driver'] == 'bridge'
                and network.get('Internal') is True and not network.get('Ingress')
                and db_id in clients and clients <= {app_id, db_id})
        if not stopped: require(app_id in clients)
    if role == 'target':
        owned = {item['id'] for item in side['containers'].values()}
        for network in {name for item in side['containers'].values() for name in item['networks']}:
            actual = json.loads(op.docker('network', 'inspect', network))[0]
            require(actual['Name'] == network and not actual.get('Ingress') and actual['Driver'] == 'bridge'
                    and set(actual.get('Containers', {})) <= owned)
    return result


def preflight(plan):
    current = host_id()
    require(current in plan['hosts'].values())
    if current == plan['hosts']['source']:
        state = inspect_side(plan, 'source')
        metadata = op.config_metadata(state['app']['Id'])
        require(metadata['prefix'] == plan['prefix'])
        require(op.db_inventory(state['db']['Id'], plan['prefix'])['schema'] == 717)
    else:
        state = inspect_side(plan, 'target', stopped=True)
        require(op.database(state['db']['Id'], 'SHOW TABLES;') == [])


def selected_files(plan, archive):
    inventory = op.archive_inventory(archive)
    exact = {'application/config/config.php', 'application/config/security.php', 'application/config/allowed_hosts.php'}
    roots = ['upload/', 'tmp/'] + ['plugins/' + name + '/' for name in plan['custom_plugins']] + ['themes/' + name + '/' for name in plan['custom_themes']]
    selected = {name: digest for name, digest in inventory.items() if name in exact or any(name.startswith(root) for root in roots)}
    require(all(not digest.startswith('LINK:') for digest in selected.values()))
    # A selected file below a linked ancestor could escape the extraction root.
    for name in selected:
        require(all(not inventory.get(str(parent), '').startswith('LINK:') for parent in Path(name).parents))
    require(all(name in selected for name in ('application/config/config.php', 'application/config/security.php')))
    for key in ('plugins', 'themes'):
        for name in plan['custom_' + key]:
            require(any(p.startswith(key + '/' + name + '/') for p in selected))
    return selected


def receipt(plan):
    directory = private_directory(plan['directory'])
    value = op.load_private(directory / 'backup.json')
    require(value.get('status') == 'PAIRED_SCHEMA717_BACKUP' and value.get('plan_sha256') == plan['_sha256']
            and value.get('source_host') == plan['hosts']['source'] and value.get('transaction') == plan['transaction'])
    require(value['inventory']['schema'] == 717 and value['inventory']['prefix'] == plan['prefix'])
    for name in ('database.sql', 'files.tar.gz'):
        path = op.protected(directory / name)
        require(path.stat().st_size > 0 and op.file_hash(path) == value['sha256'][name])
    require(value['files'] == selected_files(plan, directory / 'files.tar.gz'))
    return value


def helper(plan, arguments, script):
    container = op.docker('create', '--network', 'none', '--user', '0', '--label', LABEL + '=' + plan['_sha256'],
                          *arguments, '--entrypoint', 'sh', plan['target']['containers']['app']['image'], '-eu', '-c', script).decode().strip()
    require(re.fullmatch(HEX, container))
    op.docker('start', '-a', container, timeout=300)
    actual = json.loads(op.docker('inspect', container))[0]
    require(actual['Id'] == container and actual['Config']['Labels'].get(LABEL) == plan['_sha256'] and actual['State']['ExitCode'] == 0)
    op.docker('rm', container)


def backup(plan):
    directory = private_directory(plan['directory'])
    require(host_id() == plan['hosts']['source'])
    if (directory / 'backup.json').exists():
        inspect_side(plan, 'source', stopped=True)
        return receipt(plan)
    require(not any((directory / name).exists() for name in ('backup-started.json', 'database.sql', 'files.tar.gz')))
    state = inspect_side(plan, 'source')
    db = state['db']['Id']
    metadata = op.config_metadata(state['app']['Id'])
    require(metadata['prefix'] == plan['prefix'] and op.db_inventory(db, plan['prefix'])['schema'] == 717)
    op.save_private(directory / 'backup-started.json', {'plan_sha256': plan['_sha256'], 'status': 'FENCING'})
    op.docker('stop', '-t', '30', state['nginx']['Id'], state['app']['Id'], timeout=90)
    inspect_side(plan, 'source', stopped=True)
    inventory = op.db_inventory(db, plan['prefix']); require(inventory['schema'] == 717)
    # stdout goes directly to a protected file, never the terminal or task logs.
    dump = directory / 'database.sql'
    descriptor = os.open(dump, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        result = subprocess.run(['docker', 'exec', db, 'sh', '-eu', '-c',
            'export MYSQL_PWD=$MARIADB_ROOT_PASSWORD; exec mariadb-dump --lock-all-tables --quick --routines --events --triggers --user=root "$MARIADB_DATABASE"'], stdout=stream, stderr=subprocess.PIPE, timeout=300)
        require(result.returncode == 0)
    # Isolated helper reads all app mounts; source remains stopped on failure.
    container = op.docker('create', '--network', 'none', '--user', '0', '--label', LABEL + '=' + plan['_sha256'],
        '--volumes-from', state['app']['Id'] + ':ro', '--entrypoint', 'sh', state['app']['Config']['Image'], '-eu', '-c',
        'umask 077; tar -C /var/www/html -czf /tmp/paired.tar.gz .').decode().strip()
    require(re.fullmatch(HEX, container))
    op.docker('start', '-a', container, timeout=300)
    check = json.loads(op.docker('inspect', container))[0]
    require(check['Id'] == container and check['Config']['Labels'].get(LABEL) == plan['_sha256'] and check['State']['ExitCode'] == 0)
    files = directory / 'files.tar.gz'
    # Precreate the output privately before docker cp writes it.
    descriptor = os.open(files, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(descriptor)
    op.docker('cp', container + ':/tmp/paired.tar.gz', str(files), timeout=300); files.chmod(0o600)
    op.docker('rm', container)
    require(op.db_inventory(db, plan['prefix']) == inventory)
    inspect_side(plan, 'source', stopped=True)
    value = {'status': 'PAIRED_SCHEMA717_BACKUP', 'transaction': plan['transaction'], 'plan_sha256': plan['_sha256'],
             'source_host': host_id(), 'inventory': inventory, 'files': selected_files(plan, files),
             'sha256': {name: op.file_hash(directory / name) for name in ('database.sql', 'files.tar.gz')}}
    op.save_private(directory / 'backup.json', value)
    return receipt(plan)


def verify_restored_files(plan, pair):
    directory = Path(plan['directory'])
    op.save_private(directory / 'restore-inventory.json', pair['files'])
    mounts = []
    for kind in ('code', *KINDS):
        mounts += ['--mount', 'type=volume,src=' + plan['target']['volumes'][kind] + ',dst=' + op.VOLUMES[kind] + ',readonly']
    mounts += ['--mount', 'type=bind,src=' + str(directory / 'restore-inventory.json') + ',dst=/restore-inventory.json,readonly']
    verifier = 'foreach(json_decode(file_get_contents("/restore-inventory.json"),true) as $p=>$h){if(hash_file("sha256","/var/www/html/".$p)!==$h){exit(1);}}'
    helper(plan, mounts, "php -r '" + verifier + "'")


def restore(plan):
    require(host_id() == plan['hosts']['target'])
    directory = private_directory(plan['directory'])
    pair = receipt(plan)  # Validate every transfer byte before target mutations.
    state = inspect_side(plan, 'target', stopped=True)
    db = state['db']['Id']
    completed = directory / 'restored.json'
    if completed.exists():
        prior = op.load_private(completed)
        require(prior == {'status': 'PRIVATE_RESTORE_VERIFIED', 'plan_sha256': plan['_sha256'], 'backup_sha256': op.file_hash(directory / 'backup.json'), 'target_host': host_id()})
        require(op.db_inventory(db, plan['prefix']) == pair['inventory'])
        verify_restored_files(plan, pair)
        return prior
    require(not (directory / 'restore-started.json').exists())
    require(op.database(db, 'SHOW TABLES;') == [])
    # Import is never a reset: a partial attempt requires a new isolated target.
    op.save_private(directory / 'restore-started.json', {'plan_sha256': plan['_sha256']})
    filtered = directory / 'restore-files.tar.gz'
    descriptor = os.open(filtered, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as output, tarfile.open(directory / 'files.tar.gz', 'r:gz') as source:
        for item in source:
            name = item.name.removeprefix('./')
            if name in pair['files']:
                require(item.isfile()); item.name = name
                output.addfile(item, source.extractfile(item))
    op.save_private(directory / 'restore-inventory.json', pair['files'])
    mounts = []
    for kind in ('code', *KINDS):
        mounts += ['--mount', 'type=volume,src=' + plan['target']['volumes'][kind] + ',dst=' + op.VOLUMES[kind]]
    for name in ('restore-files.tar.gz', 'restore-inventory.json'):
        mounts += ['--mount', 'type=bind,src=' + str(directory / name) + ',dst=/' + name + ',readonly']
    verifier = 'foreach(json_decode(file_get_contents("/restore-inventory.json"),true) as $p=>$h){if(hash_file("sha256","/var/www/html/".$p)!==$h){exit(1);}}'
    # Refuse existing operator state or symlinks in writable target directories.
    guards = ['test ! -e /var/www/html/application/config/security.php', 'test ! -e /var/www/html/application/config/config.php',
              'test -z "$(find /var/www/html/application/config /var/www/html/upload /var/www/html/tmp /var/www/html/plugins /var/www/html/themes -type l -print -quit)"']
    guards += ['test ! -e /var/www/html/' + kind + '/' + name for kind in ('plugins', 'themes') for name in plan['custom_' + kind]]
    helper(plan, mounts, '; '.join(guards + ['tar -C /var/www/html -xzf /restore-files.tar.gz',
        'chown -R www-data:www-data /var/www/html/application/config /var/www/html/upload /var/www/html/tmp /var/www/html/plugins /var/www/html/themes', "php -r '" + verifier + "'"]))
    with op.protected(directory / 'database.sql').open('rb') as stream:
        result = subprocess.run(['docker', 'exec', '-i', db, 'sh', '-eu', '-c',
            'export MYSQL_PWD=$MARIADB_ROOT_PASSWORD; exec mariadb --user=root "$MARIADB_DATABASE"'], stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        require(result.returncode == 0)
    require(op.db_inventory(db, plan['prefix']) == pair['inventory'])
    inspect_side(plan, 'target', stopped=True)
    value = {'status': 'PRIVATE_RESTORE_VERIFIED', 'plan_sha256': plan['_sha256'], 'backup_sha256': op.file_hash(directory / 'backup.json'), 'target_host': host_id()}
    op.save_private(completed, value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('validate-plan', 'validate', 'backup', 'verify-pair', 'restore'))
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    try:
        plan = load_plan(args.plan, args.plan_sha256)
        with locked(plan):
            if args.operation == 'validate': preflight(plan)
            elif args.operation == 'backup': backup(plan)
            elif args.operation == 'restore': restore(plan)
            elif args.operation == 'verify-pair': receipt(plan)
        print('PASS: ' + args.operation)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, tarfile.TarError):
        print('FAIL: cross-host gate; inspect private state and preserve fenced writers', file=__import__('sys').stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
