#!/usr/bin/env python3
"""Strict native MariaDB derivative evidence; no deployment authorization."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qsl, unquote, urlsplit

_spec = importlib.util.spec_from_file_location('release_artifact', Path(__file__).with_name('release-artifact.py'))
shared = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(shared)
require = shared.require
IMAGE = 'ghcr.io/cahangeorge/limesurvey-mariadb'
BASE = 'docker.io/library/mariadb@sha256:0130d92c05fbf2d82adc2b86de742eaede65b2596c65d91786f8e03cd19e6a39'
BUILDER = 'golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d'
GOSU_SHA = '6456aaa0f3c854d199d0f037f068eb97515b7513'
ARCHIVE = '33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b'
MODULES = {'github.com/moby/sys/user': ['v0.4.1', 'h1:RgjRlaDKi/Xmyrz4t8lyzXT6v2ooFeO/7xtchmhVWE0='],
           'golang.org/x/sys': ['v0.49.0', 'h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=']}
SETTINGS = {'-buildmode': 'exe', '-compiler': 'gc', '-trimpath': 'true', 'CGO_ENABLED': '0',
            'GOARCH': 'arm64', 'GOOS': 'linux', 'GOARM64': 'v8.0'}
REGRESSION_CHECKS = ('mysql', 'numeric', 'groups', 'home', 'exec', 'failure', 'fresh_init', 'nonroot_restart', 'persistence')


def run(arguments, timeout=120):
    # Own every short-lived probe too: a killed Docker CLI can leave a container.
    probe = None
    if arguments[:2] == ['docker', 'run'] and '--name' not in arguments:
        probe = 'gosu-probe-' + secrets.token_hex(8)
        arguments = arguments[:2] + ['--name', probe] + arguments[2:]
    try:
        return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=timeout).stdout
    finally:
        if probe:
            subprocess.run(['docker', 'rm', '-f', '-v', probe], capture_output=True, timeout=60)
            absent = subprocess.run(['docker', 'ps', '-aq', '--filter', 'name=^/' + probe + '$'],
                                    check=True, capture_output=True, text=True, timeout=60)
            require(not absent.stdout.strip(), 'owned probe cleanup failed')


def identity(value):
    require(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value), 'invalid image identity')
    return value


def validate_build(build):
    require(build.get('source') == GOSU_SHA and build.get('archive_sha256') == ARCHIVE
            and build.get('compiler') == 'go1.27.2' and build.get('modules') == MODULES
            and build.get('settings') == SETTINGS and build.get('path') == 'github.com/tianon/gosu'
            and build.get('main') in ('(devel)', 'v1.19') and build.get('version') == '1.19'
            and build.get('static_arm64') is True
            and isinstance(build.get('sha256'), str) and re.fullmatch(r'[0-9a-f]{64}', build['sha256']),
            'gosu source/compiler/dependency/static identity mismatch')


def validate_regression(proof, image_id, build):
    require(proof.get('status') == 'PASS' and proof.get('cleanup') is True
            and proof.get('image_id') == image_id and proof.get('binary_sha256') == build['sha256']
            and proof.get('checks') == list(REGRESSION_CHECKS), 'missing exact-image runtime or cleanup proof')


def validate_parent(parent, image):
    require(isinstance(parent, list) and len(parent) == 1 and BASE in parent[0].get('RepoDigests', [])
            and parent[0].get('Os') == 'linux' and parent[0].get('Architecture') == 'arm64', 'unapproved parent image')
    identity(parent[0]['Id'])
    # All runtime configuration is preserved except wrapper labels.
    left = {k: v for k, v in parent[0]['Config'].items() if k != 'Labels'}
    right = {k: v for k, v in image['Config'].items() if k != 'Labels'}
    require(left == right, 'official parent runtime configuration changed')
    wrapper_labels = {'org.opencontainers.image.source', 'org.opencontainers.image.revision',
                      'org.opencontainers.image.version', 'io.omnestack.limesurvey.component'}
    require(all(image['Config'].get('Labels', {}).get(k) == v for k, v in parent[0]['Config'].get('Labels', {}).items()
                if k not in wrapper_labels),
            'official parent labels changed')
    parent_layers = parent[0].get('RootFS', {}).get('Layers')
    if parent_layers is not None:
        require(image.get('RootFS', {}).get('Layers', [])[:-1] == parent_layers, 'derivative parent layers changed')


def validate_candidate_image(images, sha):
    require(re.fullmatch(r'[0-9a-f]{40}', sha) and isinstance(images, list) and len(images) == 1, 'invalid candidate/source')
    image = images[0]; identity(image['Id'])
    require(image.get('Os') == 'linux' and image.get('Architecture') == 'arm64', 'wrong candidate platform')
    labels = image['Config']['Labels']
    require(labels.get('org.opencontainers.image.source') == shared.SOURCE
            and labels.get('org.opencontainers.image.revision') == sha
            and labels.get('org.opencontainers.image.version') == '11.4.13-noble-gosu1.19'
            and labels.get('io.omnestack.limesurvey.component') == 'mariadb', 'candidate provenance mismatch')
    return image


def binary_info(image):
    identity(image)
    name = 'gosu-inventory-' + secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix='gosu-inventory-') as directory:
        path = Path(directory) / 'gosu'
        try:
            run(['docker', 'create', '--name', name, '--network', 'none', image])
            run(['docker', 'cp', name + ':/usr/local/bin/gosu', str(path)])
            entrypoint = Path(directory) / 'entrypoint'
            run(['docker', 'cp', name + ':/usr/local/bin/docker-entrypoint.sh', str(entrypoint)])
            text = run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                        '--mount', 'type=bind,src=' + directory + ',dst=/evidence,readonly',
                        '--entrypoint', 'go', BUILDER, 'version', '-m', '/evidence/gosu'])
            raw = path.read_bytes()
            static = raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] == 183
            offset = struct.unpack_from('<Q', raw, 32)[0]
            width, count = struct.unpack_from('<HH', raw, 54)
            static = static and all(struct.unpack_from('<I', raw, offset + i * width)[0] not in (2, 3) for i in range(count))
            # -trimpath intentionally omits linker flags from Go build info.
            # An ELF symbol table proves the forbidden -s stripping was not used.
            section_offset = struct.unpack_from('<Q', raw, 40)[0]
            section_width, section_count, strings_index = struct.unpack_from('<HHH', raw, 58)
            string_header = section_offset + section_width * strings_index
            strings_offset, strings_size = struct.unpack_from('<QQ', raw, string_header + 24)
            names = raw[strings_offset:strings_offset + strings_size]
            symbols = any(names[struct.unpack_from('<I', raw, section_offset + i * section_width)[0]:].split(b'\0', 1)[0] == b'.symtab'
                          for i in range(section_count))
            static = static and symbols
            build = {'compiler': text.splitlines()[0].split()[-1], 'modules': {}, 'settings': {},
                     'source': GOSU_SHA, 'archive_sha256': ARCHIVE, 'sha256': hashlib.sha256(raw).hexdigest(),
                     'entrypoint_sha256': hashlib.sha256(entrypoint.read_bytes()).hexdigest(), 'static_arm64': static,
                     'version': run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', '/usr/local/bin/gosu', image, '--version']).split()[0]}
            for line in text.splitlines()[1:]:
                fields = line.strip().split('\t')
                if fields[0] == 'path': build['path'] = fields[1]
                elif fields[0] == 'mod': build['main'] = fields[2]
                elif fields[0] == 'dep':
                    require(fields[1] not in build['modules'], 'duplicate module'); build['modules'][fields[1]] = fields[2:4]
                elif fields[0] == '=>': raise shared.GateError('replaced Go module')
                elif fields[0] == 'build':
                    key, _, value = fields[1].partition('=')
                    require(key not in build['settings'], 'duplicate Go setting')
                    build['settings'][key] = value.strip('"')
            return build
        finally:
            run(['docker', 'rm', '-f', '-v', name])


def extract_inventory(image):
    identity(image)
    os_raw = run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', image, '/etc/os-release'])
    family, version = shared.parse_os_release(os_raw)
    require((family, version) == ('ubuntu', '24.04'), 'wrong database OS')
    raw = run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'dpkg-query', image,
               '-W', '-f=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n'])
    packages = []
    for line in raw.splitlines():
        status, name, release, architecture = line.split('\t')
        if status == 'installed': packages.append([name, release, architecture])
    require(packages and len({p[0] for p in packages}) == len(packages), 'ambiguous dpkg inventory')
    build = binary_info(image); validate_build(build)
    return {'image_id': image, 'os_family': family, 'os_version': version, 'os': packages, 'gosu': build}


def purl_identity(purl, kind, name, version, architecture=None):
    require(isinstance(purl, str) and not re.search(r'%(?![0-9A-Fa-f]{2})', purl) and '#' not in purl, 'malformed PURL')
    parsed = urlsplit(purl); package, sep, release = parsed.path.rpartition('@')
    prefix = 'deb/ubuntu/' if kind == 'ubuntu' else 'golang/'
    qualifiers = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    require(len(qualifiers) == len(dict(qualifiers)), 'duplicate PURL qualifier')
    wanted_version = version
    if kind == 'ubuntu':
        epoch, colon, base_version = version.partition(':')
        wanted_version = base_version if colon else version
        require(not colon or re.fullmatch(r'[1-9][0-9]*', epoch), 'invalid package epoch')
        arch = architecture if architecture is not None else dict(qualifiers).get('arch')
        require(arch in ('arm64', 'all'), 'OS PURL architecture mismatch')
        wanted = {'arch': arch, 'distro': 'ubuntu-24.04'}
        if colon: wanted['epoch'] = epoch
        require(dict(qualifiers) == wanted, 'OS PURL qualifiers mismatch')
    else:
        require(not qualifiers, 'unexpected Go PURL qualifiers')
    require(parsed.scheme == 'pkg' and not parsed.netloc and package.startswith(prefix) and sep
            and unquote(package[len(prefix):], errors='strict') == name
            and unquote(release, errors='strict') == wanted_version, 'package PURL identity mismatch')
    return purl


def validate_scan(report, inventory, db, image_id, artifact, now, ref=None):
    validate_build(inventory['gosu'])
    require(inventory.get('image_id') == image_id and inventory.get('os_family') == 'ubuntu'
            and inventory.get('os_version') == '24.04', 'installed inventory identity mismatch')
    require(report.get('SchemaVersion') == 2 and report.get('ArtifactName') == artifact
            and report.get('ArtifactType') == 'container_image'
            and report.get('Trivy', {}).get('Version') == '0.75.0', 'scan identity/tool mismatch')
    metadata = report['Metadata']
    require(metadata.get('ImageID') == image_id
            and metadata.get('ImageConfig', {}).get('architecture') == 'arm64'
            and metadata.get('ImageConfig', {}).get('os') == 'linux', 'scan image/platform mismatch')
    require((ref in metadata.get('RepoDigests', [])) if ref else report.get('ArtifactID') == image_id, 'scan digest mismatch')
    os = metadata['OS']
    require(os.get('Family') == 'ubuntu' and os.get('Name') == '24.04'
            and os.get('Eosl', False) is False and os.get('EOSL', False) is False, 'OS scan mismatch/EOL')
    shared.check_db(db, now)
    results = report.get('Results'); require(isinstance(results, list) and len(results) == 2, 'missing/extra scan coverage')
    os_results = [r for r in results if r.get('Class') == 'os-pkgs' and r.get('Type') == 'ubuntu']
    go_results = [r for r in results if r.get('Class') == 'lang-pkgs' and r.get('Type') == 'gobinary'
                  and r.get('Target') == 'usr/local/bin/gosu']
    require(len(os_results) == len(go_results) == 1, 'missing Ubuntu/gosu scan')
    require(os_results[0].get('Target') == artifact + ' (ubuntu 24.04)', 'OS scan target mismatch')
    require(shared.pairs(os_results[0].get('Packages'), 'Name', 'Version', debian=True)
            == shared.pairs(inventory['os'], 0, 1), 'incomplete installed OS coverage')
    require(all(isinstance(p, list) and len(p) == 3 and p[2] in ('arm64', 'all') for p in inventory['os']),
            'missing installed OS architecture')
    installed_arch = {p[0]: p[2] for p in inventory['os']}
    expected = {(name, value[0]) for name, value in MODULES.items()} | {('stdlib', 'v1.27.2')}
    main = inventory['gosu']['main']
    actual = shared.pairs(go_results[0].get('Packages'), 'Name', 'Version')
    # Trivy may include the archive main module; it must match build metadata.
    require(actual in (expected, expected | {('github.com/tianon/gosu', main)}), 'Go compiler/module coverage mismatch')
    purls = set()
    for result in results:
        packages = result['Packages']
        require(len(packages) == len(shared.pairs(packages, 'Name', 'Version', debian=result['Type'] == 'ubuntu')), 'duplicate scan package')
        for pkg in packages:
            version = next(iter(shared.pairs([pkg], 'Name', 'Version', debian=result['Type'] == 'ubuntu')))[1]
            architecture = installed_arch[pkg['Name']] if result['Type'] == 'ubuntu' else None
            if architecture:
                require(pkg.get('Arch') == architecture, 'scan package architecture mismatch')
            purl = purl_identity(pkg.get('Identifier', {}).get('PURL'), result['Type'], pkg['Name'], version, architecture)
            require(purl not in purls, 'duplicate PURL'); purls.add(purl)
        findings = result.get('Vulnerabilities', [])
        require(isinstance(findings, list) and all(v.get('Severity') in ('LOW', 'MEDIUM') for v in findings)
                and not result.get('Secrets'), 'blocking/unclassified findings')
    return purls


def daemon_ready(comm, executable, status, uid):
    identities = [line.split()[1:] for line in status.splitlines() if line.startswith('Uid:')]
    return (comm.strip() == 'mariadbd' and executable.strip() == '/usr/sbin/mariadbd'
            and identities == [[uid] * 4])


def regression(image, directory):
    identity(image); directory.mkdir(parents=True, exist_ok=True)
    receipt = directory / 'regression.json'; receipt.unlink(missing_ok=True)
    build = binary_info(image); validate_build(build)
    prefix = 'mariadb-gate-' + secrets.token_hex(8); volume = prefix + '-data'; container = prefix + '-db'
    owned = []; checks = []
    with tempfile.TemporaryDirectory(prefix=prefix) as temp:
        private = Path(temp); env = private / 'db.env'; client = private / 'client.cnf'
        password = secrets.token_hex(32)
        env.write_text('MARIADB_ROOT_PASSWORD=' + password + '\nMARIADB_DATABASE=synthetic\n'); env.chmod(0o600)
        client.write_text('[client]\nuser=root\npassword=' + password + '\n'); client.chmod(0o600)
        def docker(*args, timeout=120): return run(['docker', *args], timeout)
        def gosu(test, user, command, expected):
            name = prefix + '-' + test; owned.append(name)
            output = docker('run', '--init=false', '--name', name, '--network', 'none', '--entrypoint', 'gosu', image, user, *command).strip()
            require(output == expected, 'gosu privilege regression'); checks.append(test)
        try:
            uid = docker('run', '--rm', '--network', 'none', '--entrypoint', 'id', image, '-u', 'mysql').strip()
            gid = docker('run', '--rm', '--network', 'none', '--entrypoint', 'id', image, '-g', 'mysql').strip()
            gosu('mysql', 'mysql', ['id', '-u'], uid)
            gosu('numeric', uid + ':' + gid, ['id', '-u'], uid)
            gosu('groups', 'mysql', ['id', '-G'], gid)
            home = docker('run', '--rm', '--network', 'none', '--entrypoint', 'getent', image, 'passwd', 'mysql').split(':')[5]
            gosu('home', 'mysql', ['sh', '-c', 'printf %s "$HOME"'], home)
            gosu('exec', 'mysql', ['sh', '-c', 'test "$$" = 1 && printf exec'], 'exec')
            for args in [('missing-gosu-user', 'true'), ('mysql', 'sh', '-c', 'exit 37')]:
                name = prefix + '-failure-' + secrets.token_hex(3); owned.append(name)
                try: docker('run', '--name', name, '--network', 'none', '--entrypoint', 'gosu', image, *args)
                except subprocess.CalledProcessError as error:
                    require(error.returncode == (37 if args[0] == 'mysql' else 1), 'gosu failure semantics')
                else: raise shared.GateError('gosu failure accepted')
            checks.append('failure')
            docker('volume', 'create', volume)
            def start(nonroot=False):
                owned.append(container)
                args = ['run', '-d', '--init=false', '--name', container, '--network', 'none', '--env-file', str(env),
                        '--mount', 'type=volume,src=' + volume + ',dst=/var/lib/mysql',
                        '--mount', 'type=bind,src=' + str(client) + ',dst=/run/synthetic-client.cnf,readonly']
                if nonroot: args += ['--user', uid + ':' + gid]
                docker(*args, image)
                for _ in range(60):
                    try:
                        # The initialization shell's temporary SQL server is not readiness.
                        comm = docker('exec', '--user', uid + ':' + gid, container, 'cat', '/proc/1/comm')
                        executable = docker('exec', '--user', uid + ':' + gid, container, 'readlink', '/proc/1/exe')
                        status = docker('exec', '--user', uid + ':' + gid, container, 'cat', '/proc/1/status')
                        if not daemon_ready(comm, executable, status, uid):
                            time.sleep(2)
                            continue
                        docker('exec', '--user', '0', container, 'mariadb', '--defaults-extra-file=/run/synthetic-client.cnf', '-Nse', 'SELECT 1', timeout=10)
                        docker('exec', container, 'healthcheck.sh', '--connect', '--innodb_initialized', timeout=30)
                        return
                    except subprocess.SubprocessError: time.sleep(2)
                raise shared.GateError('database startup failed')
            def sql(query): return docker('exec', '--user', '0', container, 'mariadb', '--defaults-extra-file=/run/synthetic-client.cnf', '-Nse', query).strip()
            start(); checks.append('fresh_init')
            require('11.4.13-MariaDB' in sql('SELECT VERSION()'), 'database version mismatch')
            sql('CREATE TABLE synthetic.proof (id INT PRIMARY KEY, value VARCHAR(32)); INSERT INTO synthetic.proof VALUES (1, "owned-synthetic-row")')
            docker('stop', '--time', '30', container); docker('rm', container)
            start(True); checks.append('nonroot_restart')
            require(sql('SELECT value FROM synthetic.proof WHERE id=1') == 'owned-synthetic-row'
                    and sql('SELECT COUNT(*) FROM information_schema.columns WHERE table_schema="synthetic" AND table_name="proof"') == '2', 'persistence/schema regression')
            checks.append('persistence')
        finally:
            # Cleanup must succeed before any PASS receipt, including after a failed test.
            cleanup_ok = True
            for command in ([['docker', 'rm', '-f', '-v', name] for name in dict.fromkeys(owned)]
                            + [['docker', 'volume', 'rm', '-f', volume]]):
                try: run(command)
                except (OSError, subprocess.SubprocessError): cleanup_ok = False
            require(cleanup_ok, 'owned cleanup failed')
            require(not run(['docker', 'ps', '-aq', '--filter', 'name=' + prefix]).strip()
                    and not run(['docker', 'volume', 'ls', '-q', '--filter', 'name=' + volume]).strip(), 'owned cleanup failed')
    proof = {'schema_version': 1, 'status': 'PASS', 'image_id': image, 'binary_sha256': build['sha256'],
             'checks': checks, 'cleanup': True}
    validate_regression(proof, image, build); receipt.write_text(json.dumps(proof, indent=2) + '\n')
    return proof


def candidate(root, sha, now):
    image = validate_candidate_image(shared.load(root / 'candidate-image.json'), sha)
    validate_parent(shared.load(root / 'parent-image.json'), image)
    inventory = shared.load(root / 'inventory.json'); validate_build(inventory['gosu'])
    build = shared.load(root / 'buildinfo.json'); require(build == inventory['gosu'], 'build metadata differs from installed inventory')
    parent_binary = shared.load(root / 'parent-binary.json')
    require(parent_binary.get('entrypoint_sha256') == build.get('entrypoint_sha256')
            and parent_binary.get('sha256') != build['sha256'], 'entrypoint changed or gosu not replaced')
    validate_regression(shared.load(root / 'regression.json'), image['Id'], build)
    tested = shared.load(root / 'tested.json')
    require(tested.get('image_id') == image['Id'] and isinstance(tested.get('artifact'), str)
            and tested['artifact'].startswith('/'), 'tested identity mismatch')
    validate_scan(shared.load(root / 'candidate-scan.json'), inventory, shared.load(root / 'candidate-db.json'), image['Id'], tested['artifact'], now)
    return image, inventory


def manifest(root, digest, sha, run_id, attempt, now):
    (root / 'release.json').unlink(missing_ok=True)
    image, inventory = candidate(root, sha, now)
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0, 'invalid publisher run')
    raw = (root / 'registry-manifest.json').read_bytes(); identity(digest)
    require('sha256:' + hashlib.sha256(raw).hexdigest() == digest, 'registry digest mismatch')
    registry = json.loads(raw)
    require(registry.get('schemaVersion') == 2 and registry.get('mediaType') in shared.MANIFEST_TYPES
            and registry.get('layers') and registry['config']['digest'] == image['Id'], 'registry config mismatch')
    ref = IMAGE + '@' + digest; final = validate_candidate_image(shared.load(root / 'image.json'), sha)
    require(final['Id'] == image['Id'] and ref in final.get('RepoDigests', []), 'published/tested identity mismatch')
    require(shared.load(root / 'final-inventory.json') == inventory, 'published inventory changed')
    purls = validate_scan(shared.load(root / 'scan.json'), inventory, shared.load(root / 'db.json'), image['Id'], ref, now, ref)
    sbom = shared.load(root / 'sbom.cdx.json'); component = sbom['metadata']['component']
    require(sbom.get('bomFormat') == 'CycloneDX' and sbom.get('specVersion') == '1.7'
            and component.get('name') == ref and component.get('type') == 'container'
            and {'name': 'aquasecurity:trivy:ImageID', 'value': image['Id']} in component.get('properties', []), 'SBOM image mismatch')
    covered = set(); applications = 0
    for package in sbom['components']:
        if package.get('type') == 'operating-system':
            require(package.get('name') == 'ubuntu' and package.get('version') == '24.04' and not package.get('purl'), 'SBOM OS mismatch'); continue
        if package.get('type') == 'application':
            require(package.get('name') == 'usr/local/bin/gosu' and not package.get('purl')
                    and {'name': 'aquasecurity:trivy:Class', 'value': 'lang-pkgs'} in package.get('properties', [])
                    and {'name': 'aquasecurity:trivy:Type', 'value': 'gobinary'} in package.get('properties', []), 'SBOM binary target mismatch')
            applications += 1
            continue
        purl = package.get('purl')
        require(package.get('type') == 'library' and purl in purls and purl not in covered
                and package.get('bom-ref') == purl, 'SBOM package coverage mismatch')
        kind = 'ubuntu' if purl.startswith('pkg:deb/') else 'gobinary'
        purl_identity(purl, kind, package['name'], package['version']); covered.add(purl)
    require(covered == purls and applications == 1, 'incomplete SBOM coverage')
    ci = shared.preflight(shared.load(root / 'branch.json'), shared.load(root / 'runs.json'), sha, 'refs/heads/main')
    require(ci == shared.load(root / 'ci.json'), 'CI mismatch')
    files = ('registry-manifest.json', 'image.json', 'inventory.json', 'final-inventory.json', 'scan.json', 'db.json', 'sbom.cdx.json', 'ci.json',
             'branch.json', 'runs.json', 'candidate-image.json', 'candidate-scan.json', 'candidate-db.json', 'tested.json',
             'parent-image.json', 'parent-binary.json', 'buildinfo.json', 'regression.json')
    result = {'schema_version': 1, 'status': 'DATABASE_ARTIFACT_VERIFIED', 'component': 'mariadb', 'repository': shared.REPOSITORY,
              'source_commit': sha, 'image': ref, 'digest': digest, 'image_config_digest': image['Id'], 'platform': 'linux/arm64',
              'parent': BASE, 'gosu': inventory['gosu'], 'regression': shared.load(root / 'regression.json'),
              'scan': {'status': 'PASS', 'tool': 'Trivy 0.75.0', 'os_packages': len(inventory['os']), 'go_packages': 3},
              'ci': ci, 'release_run': {'id': run_id, 'attempt': attempt},
              'evidence_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files},
              'staging': {'status': 'PENDING'}, 'production': {'status': 'HOLD'}}
    (root / 'release.json').write_text(json.dumps(result, indent=2) + '\n'); return result


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='command', required=True)
    pre = commands.add_parser('preflight'); pre.add_argument('branch', type=Path); pre.add_argument('runs', type=Path); pre.add_argument('sha'); pre.add_argument('ref')
    for name in ('inventory', 'binary'):
        item = commands.add_parser(name); item.add_argument('image')
    item = commands.add_parser('regression'); item.add_argument('image'); item.add_argument('directory', type=Path)
    item = commands.add_parser('candidate'); item.add_argument('directory', type=Path); item.add_argument('sha')
    item = commands.add_parser('manifest'); item.add_argument('directory', type=Path); item.add_argument('digest'); item.add_argument('sha'); item.add_argument('run_id', type=int); item.add_argument('attempt', type=int)
    args = parser.parse_args()
    try:
        now = datetime.now(timezone.utc)
        if args.command == 'preflight': result = shared.preflight(shared.load(args.branch), shared.load(args.runs), args.sha, args.ref)
        elif args.command == 'inventory': result = extract_inventory(args.image)
        elif args.command == 'binary': result = binary_info(args.image)
        elif args.command == 'regression': result = regression(args.image, args.directory)
        elif args.command == 'candidate':
            image, _ = candidate(args.directory, args.sha, now); result = {'status': 'PASS', 'image_id': image['Id']}
        else: result = manifest(args.directory, args.digest, args.sha, args.run_id, args.attempt, now)
        print(json.dumps(result, indent=2)); return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, struct.error, subprocess.SubprocessError):
        print('mariadb_release=HOLD: missing, changed or failed evidence', file=sys.stderr); return 1

if __name__ == '__main__': sys.exit(main())
