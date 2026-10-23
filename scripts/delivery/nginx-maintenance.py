#!/usr/bin/env python3
"""Read-only component admission for an existing OCI Nginx maintenance change."""
import argparse
import copy
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
GATE_FILES = ('scripts/delivery/nginx-maintenance.py', 'scripts/ci/staging-release.py',
              'scripts/ci/nginx-release.py', 'scripts/ci/mariadb-release.py',
              'scripts/ci/sign-release.py', 'scripts/ci/release-artifact.py')
REPOSITORY = 'ghcr.io/cahangeorge/limesurvey-nginx'
SERVICES = {'app', 'db', 'nginx'}

def require(condition):
    if not condition:
        raise ValueError('maintenance requirement failed')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def fingerprint(value):
    """Canonical JSON hash; never print the underlying secret-bearing value."""
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())

def command(arguments, env=None):
    result = subprocess.run(arguments, capture_output=True, timeout=120, env=env)
    require(result.returncode == 0)
    return result.stdout


def reviewed_gate(repository, commit):
    """Check the separately supplied gate source before importing local validators."""
    require(re.fullmatch(r'[0-9a-f]{40}', commit))
    repository = Path(repository)
    require(repository.is_absolute())
    prefix = ['git', '-C', str(repository)]
    require(command(prefix + ['rev-parse', 'HEAD']).decode().strip() == commit)
    command(prefix + ['diff', '--quiet', 'HEAD', '--'])
    require(not command(prefix + ['ls-files', '--others', '--exclude-standard']).strip())
    for relative in GATE_FILES:
        path = ROOT / relative
        require(not path.is_symlink() and path.is_file()
                and path.read_bytes() == command(prefix + ['show', commit + ':' + relative]))

def initialize(repository, commit):
    reviewed_gate(repository, commit)
    spec = importlib.util.spec_from_file_location('maintenance_admission', ROOT / 'scripts/ci/staging-release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_file(value):
    path = Path(value)
    info = path.lstat()
    require(path.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600)
    return path

def file_hashes(expected):
    require(isinstance(expected, dict) and expected)
    for value, sha in expected.items():
        path = Path(value)
        require(path.is_absolute() and path.is_file() and not path.is_symlink()
                and re.fullmatch(r'[0-9a-f]{64}', sha) and digest(path.read_bytes()) == sha)

def render(adapter, env_file):
    environment = {key: value for key, value in os.environ.items() if not key.startswith('OCI_')}
    return json.loads(command(['docker', 'compose', '--env-file', str(private_file(env_file)),
                              '-f', adapter, 'config', '--format', 'json'], env=environment))


def compose_hashes(adapter, env_file):
    environment = {key: value for key, value in os.environ.items() if not key.startswith('OCI_')}
    raw = command(['docker', 'compose', '--env-file', str(private_file(env_file)),
                   '-f', adapter, 'config', '--hash', '*'], env=environment).decode()
    result = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'(app|db|nginx) ([0-9a-f]{64})', line)
        require(match is not None and match[1] not in result)
        result[match[1]] = match[2]
    require(set(result) == SERVICES)
    return result

def isolation(host):
    require(host.get('PidMode', '') == '' and host.get('IpcMode', '') in ('', 'private')
            and not host.get('UTSMode') and not host.get('UsernsMode')
            and all(option in ('no-new-privileges', 'no-new-privileges:true')
                    for option in (host.get('SecurityOpt') or [])))

def limits(service, host):
    cpus = Decimal(str(service['cpus']))
    memory = int(service['mem_limit'])
    require(0 < cpus <= 1 and 0 < memory <= 512 * 1024 * 1024
            and host['NanoCpus'] == int(cpus * 1_000_000_000)
            and host['Memory'] == memory and host['MemorySwap'] == 2 * memory
            and host.get('PidsLimit') is None and host.get('MemorySwappiness') is None
            and not any(host.get(key) for key in ('CpuQuota', 'CpuPeriod', 'CpuShares',
                        'CpuRealtimePeriod', 'CpuRealtimeRuntime', 'CpusetCpus', 'CpusetMems',
                        'MemoryReservation', 'KernelMemory', 'KernelMemoryTCP', 'OomKillDisable',
                        'CpuCount', 'CpuPercent', 'BlkioWeight', 'BlkioWeightDevice',
                        'BlkioDeviceReadBps', 'BlkioDeviceWriteBps', 'BlkioDeviceReadIOps',
                        'BlkioDeviceWriteIOps', 'IOMaximumIOps', 'IOMaximumBandwidth',
                        'DeviceRequests', 'DeviceCgroupRules', 'Rdma', 'Unified', 'Ulimits',
                        'CgroupParent', 'OomScoreAdj')))

def live_nginx(config, value):
    """Bind the approved old Compose service to actual Docker runtime settings."""
    service = config['services']['nginx']
    require(set(service) == {'command', 'cpus', 'depends_on', 'entrypoint', 'healthcheck',
            'image', 'labels', 'mem_limit', 'networks', 'platform', 'ports', 'read_only',
            'restart', 'tmpfs', 'volumes'})
    host = value['HostConfig']
    isolation(host)
    limits(service, host)
    require(service['platform'] == 'linux/arm64' and service['read_only'] is True
            and host['ReadonlyRootfs'] is True and service['restart'] == 'unless-stopped'
            and host['RestartPolicy'] == {'Name': 'unless-stopped', 'MaximumRetryCount': 0}
            and service['labels'] == {'traefik.enable': 'false'}
            and all(value['Config']['Labels'].get(k) == v for k, v in service['labels'].items())
            and not any(host.get(k) for k in ('Privileged', 'CapAdd', 'Devices', 'ExtraHosts',
                                             'Links', 'Dns', 'DnsSearch', 'PublishAllPorts')))
    image = inspect('image', service['image'])
    require(image['Id'] == value['Image'] and service['image'] in image['RepoDigests']
            and image['Architecture'] == 'arm64' and image['Os'] == 'linux')
    for compose_key, docker_key in (('command', 'Cmd'), ('entrypoint', 'Entrypoint')):
        setting = service[compose_key]
        require(setting is None or isinstance(setting, list))
        require(value['Config'][docker_key] == (image['Config'][docker_key] if setting is None else setting))
    require(set(service['networks']) == {'application', 'proxy'}
            and all(not options for options in service['networks'].values())
            and set(value['NetworkSettings']['Networks']) ==
                {config['networks'][name]['name'] for name in service['networks']}
            and host['NetworkMode'] in value['NetworkSettings']['Networks'])
    require(service['tmpfs'] == ['/var/cache/nginx', '/var/run']
            and host['Tmpfs'] == {path: '' for path in service['tmpfs']})
    require(len(service['ports']) == 1)
    port = service['ports'][0]
    require(set(port) == {'host_ip', 'mode', 'protocol', 'published', 'target'}
            and port['host_ip'] == '127.0.0.1' and port['mode'] == 'ingress'
            and port['protocol'] == 'tcp' and port['target'] == 80
            and 1024 <= int(port['published']) <= 65535)
    ports = {'80/tcp': [{'HostIp': port['host_ip'], 'HostPort': str(port['published'])}]}
    require(host['PortBindings'] == ports and value['NetworkSettings']['Ports'] == ports)
    mounts = []
    for mount in service['volumes']:
        require(set(mount) <= {'type', 'source', 'target', 'read_only', 'bind', 'volume'}
                and mount['type'] in ('volume', 'bind') and mount['read_only'] is True
                and not mount.get('volume')
                and set(mount.get('bind', {})) <= {'create_host_path'})
        source = (config['volumes'][mount['source']]['name'] if mount['type'] == 'volume' else mount['source'])
        mounts.append((mount['type'], source, mount['target'], False))
    actual = [(m['Type'], m['Name'] if m['Type'] == 'volume' else m['Source'], m['Destination'], m['RW'])
              for m in value['Mounts']]
    require(len(mounts) == 6 and len(set(mounts)) == 6 and sorted(mounts) == sorted(actual))


def compose_pair(before, after, expected):
    project = expected['project']
    require(re.fullmatch(r'ls-oci-[a-z0-9][a-z0-9-]{3,40}', project)
            and before['name'] == after['name'] == project
            and set(before['services']) == set(after['services']) == SERVICES
            and fingerprint(before) == expected['compose_sha256'])
    old, new = before['services']['nginx']['image'], expected['candidate']['image']
    require(re.fullmatch(re.escape(REPOSITORY) + r'@sha256:[0-9a-f]{64}', old)
            and old == expected['rollback_image'] and old != new)
    changed = copy.deepcopy(before)
    changed['services']['nginx']['image'] = new
    require(after == changed)
    return project

def inspect(kind, value):
    result = json.loads(command(['docker', kind, 'inspect', value]))
    require(isinstance(result, list) and len(result) == 1)
    return result[0]

def container_fingerprint(value):
    return fingerprint({key: value[key] for key in
                        ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'Mounts', 'RestartCount')}
                       | {'StartedAt': value['State']['StartedAt']}
                       | {'Networks': value['NetworkSettings']['Networks']})

def healthy(value):
    require(value['State']['Status'] == 'running' and value['State']['Health']['Status'] == 'healthy'
            and not value['State'].get('Restarting') and not value['State'].get('Dead'))

def observe(expected, config):
    project = expected['project']
    require(set(expected['containers']) == SERVICES)
    hashes = compose_hashes(expected['adapter'], expected['current_env'])
    values = {}
    for service in sorted(SERVICES):
        bound = expected['containers'][service]
        require(re.fullmatch(r'[0-9a-f]{64}', bound['id']))
        value = inspect('container', bound['id'])
        healthy(value)
        labels = value['Config']['Labels']
        require(value['Id'] == bound['id'] and value['Name'] == '/' + project + '-' + service + '-1'
                and labels['com.docker.compose.project'] == project
                and labels['com.docker.compose.service'] == service
                and labels['com.docker.compose.config-hash'] == hashes[service]
                and value['Config']['Image'] == config['services'][service]['image']
                and container_fingerprint(value) == bound['sha256'])
        values[service] = value
    live_nginx(config, values['nginx'])
    actual_ids = set(command(['docker', 'ps', '-aq', '--no-trunc', '--filter',
                             'label=com.docker.compose.project=' + project]).decode().splitlines())
    require(actual_ids == {v['Id'] for v in values.values()})
    require(set(expected['volumes']) == {v['name'] for v in config['volumes'].values()})
    require(set(expected['networks']) == {n['name'] for n in config['networks'].values()})
    for kind, key in [('volume', 'volumes'), ('network', 'networks')]:
        for name, sha in expected[key].items():
            require(fingerprint(inspect(kind, name)) == sha)
    proxy = inspect('container', expected['proxy_container']['id'])
    require(re.fullmatch(r'[0-9a-f]{64}', expected['proxy_container']['id'])
            and proxy['State']['Status'] == 'running'
            and container_fingerprint(proxy) == expected['proxy_container']['sha256']
            and config['networks']['proxy']['name'] in proxy['NetworkSettings']['Networks']
            and any(m['Type'] == 'bind' and Path(expected['proxy_config']).is_relative_to(m['Source'])
                    for m in proxy['Mounts']))
    file_hashes(expected['files_sha256'])
    require(expected['adapter'] in expected['files_sha256']
            and expected['proxy_config'] in expected['files_sha256'])
    binds = [m for m in values['nginx']['Mounts'] if m['Type'] == 'bind']
    require(len(binds) == 1 and binds[0]['Destination'] == '/etc/nginx/conf.d/default.conf'
            and binds[0]['Source'] in expected['files_sha256'] and binds[0]['RW'] is False)
    return values

def canary(expected, current, component, config):
    bound = expected['canary']
    require(re.fullmatch(r'[0-9a-f]{64}', bound['id']))
    candidate = inspect('container', bound['id'])
    healthy(candidate)
    isolation(candidate['HostConfig'])
    limits(config['services']['nginx'], candidate['HostConfig'])
    local_image = inspect('image', component['image'])
    require(local_image['Id'] == candidate['Image']
            and component['image'] in local_image['RepoDigests'])
    require(candidate['Id'] == bound['id'] and candidate['Id'] not in {v['Id'] for v in current.values()}
            and container_fingerprint(candidate) == bound['sha256']
            and candidate['Config']['Image'] == component['image']
            and candidate['Mounts'] == current['nginx']['Mounts']
            and all(m['RW'] is False for m in candidate['Mounts'] if m['Type'] != 'tmpfs')
            and all(m['Destination'] in {'/var/cache/nginx', '/var/run'}
                    for m in candidate['Mounts'] if m['Type'] == 'tmpfs')
            and candidate['HostConfig']['ReadonlyRootfs'] is True
            and candidate['HostConfig']['Tmpfs'] == current['nginx']['HostConfig']['Tmpfs']
            and not candidate['HostConfig'].get('Privileged')
            and not candidate['HostConfig'].get('CapAdd')
            and not candidate['HostConfig'].get('Devices')
            and not candidate['HostConfig'].get('PortBindings')
            and not candidate['HostConfig'].get('PublishAllPorts')
            and not any(candidate['NetworkSettings'].get('Ports', {}).values())
            and not candidate['HostConfig'].get('ExtraHosts')
            and not candidate['HostConfig'].get('Links')
            and not candidate['HostConfig'].get('Dns')
            and not candidate['HostConfig'].get('DnsSearch')
            and candidate['Config']['Labels'].get('traefik.enable') == 'false'
            and all(not key.startswith('traefik.') or key == 'traefik.enable'
                    for key in candidate['Config']['Labels'])
            and candidate['Config']['Entrypoint'] == current['nginx']['Config']['Entrypoint']
            and candidate['Config']['Cmd'] == current['nginx']['Config']['Cmd'])
    network = config['networks']['application']['name']
    require(candidate['HostConfig']['NetworkMode'] == network
            and set(candidate['NetworkSettings']['Networks']) == {network}
            and network in current['app']['NetworkSettings']['Networks'])
    # Resolve app only through the production network. Reject ambiguous app aliases.
    endpoints = inspect('network', network)['Containers']
    app_aliases = []
    for identifier in endpoints:
        peer = inspect('container', identifier)
        aliases = peer['NetworkSettings']['Networks'][network].get('Aliases') or []
        if 'app' in aliases:
            app_aliases.append(peer['Id'])
    require(app_aliases == [current['app']['Id']])
    production_config = command(['docker', 'exec', current['nginx']['Id'], 'nginx', '-T'])
    candidate_config = command(['docker', 'exec', candidate['Id'], 'nginx', '-T'])
    require(production_config == candidate_config and digest(candidate_config) == bound['nginx_config_sha256']
            and b'fastcgi_pass app:9000;' in candidate_config)
    body = command(['docker', 'exec', candidate['Id'], 'wget', '-qO-', '-T', '30',
                    'http://127.0.0.1/index.php?r=admin/authentication/sa/login'])
    require(len(body) <= 2_000_000 and all(marker in body.lower() for marker in
                                         (b'<form', b'limesurvey', b'password')))
    # Record only a body hash; login page sessions/CSRF tokens never leave the process.
    return digest(body)

def evaluate(path, sha, now, gate_repository, gate_commit):
    admission = initialize(gate_repository, gate_commit)
    expected = admission.checked(private_file(path), sha)
    require(expected.get('schema_version') == 1 and expected['gate_commit'] == gate_commit)
    # A short-lived operator-reviewed observation prevents reuse after a later change.
    age = (now - admission.timestamp(expected['observed_at'])).total_seconds()
    require(0 <= age <= 900 and re.fullmatch(r'[0-9a-f]{40}', expected['source_commit']))
    file_hashes(expected['files_sha256'])
    before = render(expected['adapter'], expected['current_env'])
    after = render(expected['adapter'], expected['candidate_env'])
    compose_pair(before, after, expected)
    current = observe(expected, before)
    component = admission.component(expected['candidate'], 'nginx', expected['source_commit'], now)
    require(component['image'] == expected['candidate']['image'])
    body_hash = canary(expected, current, component, before)
    require(render(expected['adapter'], expected['current_env']) == before
            and render(expected['adapter'], expected['candidate_env']) == after)
    observe(expected, before)
    final_canary = inspect('container', expected['canary']['id'])
    healthy(final_canary)
    require(container_fingerprint(final_canary) == expected['canary']['sha256'])
    require(0 <= (datetime.now(timezone.utc) - now).total_seconds() <= 300)
    return {'schema_version': 1, 'status': 'NGINX_MAINTENANCE_PREFLIGHT_PASS',
            'expected_sha256': sha, 'gate_commit': gate_commit, 'checked_at': now.isoformat(), 'canary_body_sha256': body_hash,
            'candidate': component, 'production': 'HOLD',
            'pending': ['Operator single-service recreation, post-change HTTPS/admin/public checks and rollback acceptance']}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected', required=True, type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--gate-repository', required=True, type=Path)
    parser.add_argument('--gate-commit', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(evaluate(args.expected, args.expected_sha256, datetime.now(timezone.utc),
                                  args.gate_repository, args.gate_commit), indent=2))
        return 0
    except (OSError, ValueError, ArithmeticError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        print('nginx_maintenance=HOLD: missing, changed, stale or unverified evidence', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
