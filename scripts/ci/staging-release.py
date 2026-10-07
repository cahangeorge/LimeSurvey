#!/usr/bin/env python3
"""Verify the fixed synthetic staging recipe locally; never authorize deployment."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, unquote, urlsplit

_spec = importlib.util.spec_from_file_location('nginx_release', Path(__file__).with_name('nginx-release.py'))
nginx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nginx)
shared = nginx.shared
require = shared.require
DB_REF = 'docker.io/library/mariadb@sha256:0130d92c05fbf2d82adc2b86de742eaede65b2596c65d91786f8e03cd19e6a39'
DB_CONFIG = 'sha256:46d43d3c938ae9c1826af3c4093cea628499394820aab667519d72be306c6f9c'
DB_INDEX = 'sha256:1292844148b311e4ed4300022a996d39083f415a963e970cf47cad1b3b18e3a6'
GOSU = '3a8ef022d82c0bc4a98bcb144e77da714c25fcfa64dccc57f6aba7ae47ff1a44'
PROPOSAL_SHA = '737a21b09caf9b61982bbcd1669c1bddff6b1d4c34c214312ad08e6f77851d8f'
COMPOSE_SHA = '94dd36a08d0f95eeb0fc0cb4d768ba5a1fea46b94f3fa77879094ded9cab409c'
RENDER_SHA = '41df5ac4a7f24032a3be85ad910c1aea5e1e2c0976a20b951f59e52dde4e5f2c'
NGINX_CONFIG_SHA = 'f47d59d650c5edc6a6bc3ba1db6f29b4ed12b9e2b96ba11f2177c401ac3e344b'
REVIEW_AT = '2026-10-10T18:00:00Z'
EXPIRES_AT = '2026-10-14T18:00:00Z'
DB_INVENTORY_SHA = '997afaf11a412ce6942fb0ad8f3aba0458e3784b25039e714c3598864ad61426'
DB_METADATA_SHA = 'd441f7570466a3888588580504c4576a3a38c3b36ddbb1a5a7cabd0f8101f76c'
GO_MODULES = {'github.com/tianon/gosu': 'v1.19.0', 'github.com/moby/sys/user': 'v0.1.0',
              'golang.org/x/sys': 'v0.1.0', 'stdlib': 'v1.24.6'}
COMPONENTS = {
    'app': ('release-evidence-37186347292-1',
            '2ba0682875e5c6e2ae810d3c737ffc3ac9b89cd57069c48567dc46d2724c8270',
            nginx.FPM_REF, nginx.FPM_SHA, 37186347292),
    'nginx': ('nginx-release-evidence-37657981977-1',
              '34894e1fe793af53f4d9a9480a70158d5bebb6409185d153d192055f8d283b9c',
              nginx.IMAGE + '@sha256:16699f0b601082faf0c60750a20128d024788f35675831afd80a9081493bb3d9',
              'd2651b5e9c265b58703abc3eb1ec2b88b19c1852', 37657981977)}


def timestamp(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(stamp.tzinfo is not None, 'timestamp requires timezone')
    return stamp


def recent(value, now):
    require(-300 <= (now - timestamp(value)).total_seconds() <= 86400,
            'stale or future-dated scan/Go refresh')


def within(root, name):
    path = root / name
    require(isinstance(name, str) and not Path(name).is_absolute()
            and path.resolve().is_relative_to(root.resolve()), 'evidence path escape')
    return path


def checked(path, digest):
    require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest), 'invalid evidence hash')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, 'evidence hash mismatch')
    return json.loads(raw)


def validate_authority(record, now):
    # The operator supplies the trusted hash out of band; JSON status alone is not authority.
    require(record.get('status') == 'ACCEPTED' and record.get('owner') == 'gion'
            and record.get('scope') == 'isolated-synthetic-staging'
            and record.get('proposal_sha256') == PROPOSAL_SHA
            and record.get('review_at') == REVIEW_AT and record.get('expires_at') == EXPIRES_AT,
            'missing or broadened exact staging acceptance')
    require(now < timestamp(REVIEW_AT) and now < timestamp(EXPIRES_AT),
            'review due or disposition expired; fresh explicit review required')


def validate_db(report, inventory, db, policy, now):
    require((policy.get('image'), policy.get('image_config_digest'), policy.get('index_digest'),
             policy.get('gosu_sha256'), policy.get('platform'), policy.get('target')) ==
            (DB_REF, DB_CONFIG, DB_INDEX, GOSU, 'linux/arm64', 'usr/local/bin/gosu'), 'wrong disposition artifact')
    require(inventory.get('image_leaf') == DB_REF.split('@')[1] and inventory.get('gosu_sha256') == GOSU,
            'wrong independently extracted DB/gosu identity')
    require(report.get('SchemaVersion') == 2 and report.get('ArtifactType') == 'container_image'
            and report.get('ArtifactName') == DB_REF and report.get('Trivy', {}).get('Version') == '0.75.0',
            'wrong DB scan/tool')
    metadata = report['Metadata']
    require(metadata.get('ImageID') == DB_CONFIG
            and any(ref in metadata.get('RepoDigests', []) for ref in
                    (DB_REF, 'mariadb@' + DB_REF.split('@')[1]))
            and metadata.get('ImageConfig', {}).get('architecture') == 'arm64'
            and metadata.get('ImageConfig', {}).get('os') == 'linux'
            and metadata.get('OS', {}).get('Family') == 'ubuntu'
            and metadata.get('OS', {}).get('Name') == '24.04'
            and not metadata['OS'].get('Eosl') and not metadata['OS'].get('EOSL'), 'wrong scanned DB platform/OS')
    recent(report['CreatedAt'], now)
    shared.check_db(db, now)
    expected = set()
    for package in inventory['installed_packages']:
        identity = (package['name'], package['version'], package['architecture'])
        require(all(isinstance(x, str) and x for x in identity) and identity not in expected,
                'invalid/duplicate installed package')
        expected.add(identity)
    require(expected, 'empty installed inventory')
    results = report['Results']
    require(isinstance(results, list) and len(results) == 2, 'incomplete/ambiguous OS and Go scan')
    os, go = results
    require((os.get('Class'), os.get('Type'), os.get('Target')) ==
            ('os-pkgs', 'ubuntu', DB_REF + ' (ubuntu 24.04)')
            and (go.get('Class'), go.get('Type'), go.get('Target')) ==
            ('lang-pkgs', 'gobinary', 'usr/local/bin/gosu'), 'wrong scan targets')
    actual = set()
    require(isinstance(os.get('Packages'), list), 'malformed OS packages')
    for package in os['Packages']:
        name, version, release, epoch = (package['Name'], package['Version'],
                                        package.get('Release', ''), package.get('Epoch', 0))
        require(isinstance(name, str) and name and isinstance(version, str) and version
                and isinstance(release, str) and type(epoch) is int and epoch >= 0, 'invalid Debian identity')
        base = version + ('-' + release if release else '')
        full = (str(epoch) + ':' if epoch else '') + base
        identity = (name, full, package['Arch'])
        require(identity not in actual and package.get('ID') == name + '@' + full,
                'duplicate or wrong Debian package ID')
        actual.add(identity)
        purl = package['Identifier']['PURL']
        require(isinstance(purl, str) and not re.search(r'%(?![0-9a-fA-F]{2})', purl), 'malformed Debian PURL')
        parsed = urlsplit(purl)
        qualifiers = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        wanted = {'arch': package['Arch'], 'distro': 'ubuntu-24.04'}
        if epoch: wanted['epoch'] = str(epoch)
        require(parsed.scheme == 'pkg' and not parsed.netloc and not parsed.fragment
                and unquote(parsed.path, errors='strict') == 'deb/ubuntu/' + name + '@' + base
                and len(qualifiers) == len(wanted) and dict(qualifiers) == wanted, 'Debian PURL identity mismatch')
    require(actual == expected, 'incomplete OS package coverage')
    modules = {}
    require(isinstance(go.get('Packages'), list), 'malformed Go packages')
    for package in go['Packages']:
        name, version = package['Name'], package['Version']
        require(name not in modules and GO_MODULES.get(name) == version
                and package.get('ID') == name + '@' + version
                and package.get('Identifier', {}).get('PURL') == 'pkg:golang/' + name + '@' + version,
                'wrong or duplicate Go module')
        modules[name] = version
    require(modules == GO_MODULES, 'incomplete Go coverage')
    allowed = set()
    for finding in policy['findings']:
        require(finding.get('applicability') == 'NO_REACHABLE_AFFECTED_SYMBOL_FOUND', 'unclassified applicability')
        identity = tuple(finding[k] for k in ('id', 'package', 'version', 'severity'))
        require(identity not in allowed, 'duplicate disposition')
        allowed.add(identity)
    found = set()
    for result in results:
        require(not result.get('Secrets') and not result.get('Misconfigurations'), 'secret/config finding blocks staging')
        findings = result.get('Vulnerabilities', [])
        require(isinstance(findings, list), 'malformed vulnerabilities')
        for finding in findings:
            severity = finding.get('Severity')
            require(severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'), 'unclassified severity')
            if severity in ('LOW', 'MEDIUM'): continue
            identity = tuple(finding[k] for k in ('VulnerabilityID', 'PkgName', 'InstalledVersion', 'Severity'))
            require(result is go and identity in allowed and identity not in found,
                    'new/unlisted/duplicate blocking finding or OS CVE')
            found.add(identity)
    require(found == allowed and found, 'incomplete accepted finding coverage')
    return {'raw_scan': 'FAIL', 'blocking_findings': len(found), 'os_packages': len(actual),
            'go_modules': len(modules), 'disposition': 'ACCEPTED_STAGING_ONLY'}


def validate_compose(path, rendered, nginx_config):
    require(hashlib.sha256(path.read_bytes()).hexdigest() == COMPOSE_SHA, 'changed Compose recipe')
    require(hashlib.sha256(nginx_config.read_bytes()).hexdigest() == NGINX_CONFIG_SHA, 'changed Nginx source config')
    normalized = {k: v for k, v in rendered.items() if k != 'x-readiness'}
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    # Exact target-provider output pins all keys, not an incomplete allowlist of dangerous options.
    require(digest == RENDER_SHA, 'changed/unverified rendered configuration or synthetic inputs')
    return {'compose_sha256': COMPOSE_SHA, 'rendered_sha256': digest,
            'nginx_source_sha256': NGINX_CONFIG_SHA, 'mounted_nginx_bytes': 'UNKNOWN',
            'network_runtime_isolation': 'UNKNOWN'}


def component(root, kind):
    directory, digest, image, sha, run = COMPONENTS[kind]
    evidence = root / directory
    release = checked(evidence / 'release.json', digest)
    require(release['image'] == image and release['source_commit'] == sha
            and release['release_run']['id'] == run and release['release_run']['attempt'] == 1
            and release['platform'] == 'linux/arm64' and release['scan']['status'] == 'PASS', 'wrong component release')
    for name, expected in release['evidence_sha256'].items():
        checked(within(evidence, name), expected) if name.endswith('.json') else require(
            hashlib.sha256(within(evidence, name).read_bytes()).hexdigest() == expected, 'component evidence changed')
    load = lambda name: shared.load(evidence / name)
    # Reproduce historical acceptance at its archived DB download time; this is NOT a fresh runtime scan.
    at = timestamp(load('db.json')['DownloadedAt'])
    validator = shared.validate_image if kind == 'app' else nginx.validate_image
    validator((evidence / 'registry-manifest.json').read_bytes(), image.split('@')[1],
              load('image.json'), load('scan.json'), load('inventory.json'), load('db.json'),
              load('sbom.cdx.json'), sha, at)
    if kind == 'nginx':
        nginx.candidate(evidence, sha, at)
        require(shared.preflight(load('branch.json'), load('runs.json'), sha, 'refs/heads/main') == load('ci.json'),
                'Nginx CI provenance changed')
    return {'image': image, 'source_commit': sha, 'release_run': release['release_run'],
            'release_sha256': digest, 'release_acceptance': 'HISTORICAL_VERIFIED',
            'fresh_runtime_rescan': 'PENDING'}


def evaluate(root, authority_path, authority_sha, compose, rendered, nginx_config, now):
    authority = checked(authority_path, authority_sha)
    validate_authority(authority, now)
    preflight = root / 'staging-preflight-20261007'
    policy = checked(preflight / 'mariadb-disposition.proposed.json', PROPOSAL_SHA)
    for name, digest in policy['evidence_sha256'].items(): checked(within(root, name), digest)
    refresh = shared.load(preflight / 'go-record-refresh.json')
    recent(refresh['checked_at'], now)
    require(refresh['status'] == 'PASS' and len(refresh['records']) == len(policy['findings']), 'missing Go record refresh')
    records = {}
    for entry in refresh['records']:
        require(entry['cve'] not in records and entry['unchanged_from_reviewed_record'] is True
                and entry['withdrawn'] is None, 'changed/duplicate/withdrawn Go record')
        raw = checked(within(preflight, 'go-records/' + entry['go_id'] + '.json'), entry['raw_sha256'])
        require(raw['id'] == entry['go_id'] and entry['cve'] in raw['aliases']
                and raw.get('withdrawn') is None and raw['modified'] == entry['modified'], 'Go record identity changed')
        records[entry['cve']] = entry['go_id']
    require(records == {f['id']: f['go_id'] for f in policy['findings']}, 'incomplete Go record mapping')
    manifest = (preflight / '11.4.13-noble-arm64-manifest.json').read_bytes()
    require('sha256:' + hashlib.sha256(manifest).hexdigest() == DB_REF.split('@')[1]
            and json.loads(manifest)['config']['digest'] == DB_CONFIG, 'DB registry leaf/config mismatch')
    index_raw = (preflight / '11.4.13-noble-index.json').read_bytes()
    require('sha256:' + hashlib.sha256(index_raw).hexdigest() == DB_INDEX, 'DB index changed')
    leaves = [m for m in json.loads(index_raw)['manifests'] if m.get('platform', {}).get('os') == 'linux'
              and m.get('platform', {}).get('architecture') == 'arm64']
    require(len(leaves) == 1 and leaves[0]['digest'] == DB_REF.split('@')[1], 'ambiguous/wrong ARM64 leaf')
    db = validate_db(shared.load(preflight / '11.4.13-noble-scan.json'),
                     checked(preflight / 'noble-installed-inventory.json', DB_INVENTORY_SHA),
                     checked(preflight / '11.4.13-noble-scan-db.json', DB_METADATA_SHA), policy, now)
    config = validate_compose(compose, shared.load(rendered), nginx_config)
    return {'schema_version': 1, 'status': 'LOCAL_STAGING_CANDIDATE_WITH_ACCEPTED_DISPOSITION',
            'checked_at': now.isoformat(), 'authority_sha256': authority_sha, 'proposal_sha256': PROPOSAL_SHA,
            'components': {kind: component(root, kind) for kind in COMPONENTS},
            'db': {'image': DB_REF, **db, 'review_at': REVIEW_AT, 'expires_at': EXPIRES_AT},
            'configuration': config, 'staging_deployable': False, 'production': 'HOLD',
            'pending': ['Fresh PHP/Nginx/DB scans and host capacity before execution',
                        'Separate runtime provisioning and DB initialization authority',
                        'Coolify adapter, fresh volumes, private route and literal mounted config',
                        'Runtime egress boundary, application/DB/browser and persistence acceptance']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('evidence_root', 'authority', 'compose', 'rendered', 'nginx_config'):
        parser.add_argument('--' + name.replace('_', '-'), required=True, type=Path)
    parser.add_argument('--authority-sha256', required=True)
    args = parser.parse_args()
    try:
        result = evaluate(args.evidence_root, args.authority, args.authority_sha256,
                          args.compose, args.rendered, args.nginx_config, datetime.now(timezone.utc))
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        # No output files are created; an old report is never an executable authorization.
        print('staging_release=HOLD: missing, changed, stale or unapproved evidence', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
