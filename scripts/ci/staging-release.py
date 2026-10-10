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
PROPOSAL_SHA = '9841ff3bccd351a02202fb809eb902908267f87c827ae443c8c905cf85b7ea02'
COMPOSE_SHA = 'b8814fdada2da18939c7a02b210117c0239a1e3cfe8c59236f1f683682e5baef'
RENDER_SHA = '5e581a5f0aa86be271afa083834b92785ecc477638ea9b0f80925b36514b6239'
NGINX_CONFIG_SHA = 'f47d59d650c5edc6a6bc3ba1db6f29b4ed12b9e2b96ba11f2177c401ac3e344b'
REVIEW_AT = '2026-10-11T12:00:00Z'
EXPIRES_AT = '2026-10-14T18:00:00Z'
DB_INVENTORY_SHA = '997afaf11a412ce6942fb0ad8f3aba0458e3784b25039e714c3598864ad61426'
DB_METADATA_SHA = 'ffaec9a63590dcd467fbb7d88b4ab35c8353d808ef5df64bb63a3a5b9a5d3d81'
GO_MODULES = {'github.com/tianon/gosu': 'v1.19.0', 'github.com/moby/sys/user': 'v0.1.0',
              'golang.org/x/sys': 'v0.1.0', 'stdlib': 'v1.24.6'}
COMPONENTS = {
    'app': ('release-evidence-37186347292-1',
            '2ba0682875e5c6e2ae810d3c737ffc3ac9b89cd57069c48567dc46d2724c8270',
            nginx.FPM_REF, nginx.FPM_SHA, 37186347292),
    'nginx': ('nginx-tiff-publication-20261010/release-evidence',
              '71c01dd5ca3f76310ab1a67d568a4044bcc75bfbb47ad9ac1c070ee1b87131a9',
              nginx.IMAGE + '@sha256:a8eeb20f935ef074537bdafe1151dae2892ce381f97305edc448af1647a061f4',
              '2b7abac451afb0ce74aae735fe8b62d5ce171b41', 38053603034)}


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


def component(root, kind, now):
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
    # Bind fresh PHP evidence to the original inventory/SBOM; Nginx publication is still current.
    fresh = root / 'published-readiness-20261010'
    report = shared.load(fresh / 'app-scan.json') if kind == 'app' else load('scan.json')
    db = shared.load(fresh / 'app-scan-db.json') if kind == 'app' else load('db.json')
    recent(report['CreatedAt'], now)
    validator = shared.validate_image if kind == 'app' else nginx.validate_image
    validator((evidence / 'registry-manifest.json').read_bytes(), image.split('@')[1],
              load('image.json'), report, load('inventory.json'), db,
              load('sbom.cdx.json'), sha, now)
    if kind == 'nginx':
        nginx.candidate(evidence, sha, now)
        require(shared.preflight(load('branch.json'), load('runs.json'), sha, 'refs/heads/main') == load('ci.json'),
                'Nginx CI provenance changed')
    return {'image': image, 'source_commit': sha, 'release_run': release['release_run'],
            'release_sha256': digest, 'release_acceptance': 'VERIFIED_WITH_CURRENT_SCAN',
            'fresh_scan_checked_at': now.isoformat(), 'rescan_before_runtime': 'REQUIRED'}


def validate_records(root, refresh, policy, now):
    recent(refresh['checked_at'], now)
    require(refresh['status'] == 'PASS_OFFICIAL_RECORD_REFRESH_ONLY_NO_RISK_ACCEPTANCE',
            'missing official Go record refresh')
    all_records, blocking = {}, {}
    for entry in refresh['records']:
        require(entry['cve'] not in all_records and entry['unchanged_from_9Oct'] is True
                and entry['withdrawn'] is None, 'changed/duplicate/withdrawn Go record')
        raw = checked(within(root, 'go-records/' + entry['go_id'] + '.json'), entry['sha256'])
        require(raw['id'] == entry['go_id'] and entry['cve'] in raw['aliases']
                and raw.get('withdrawn') is None and raw['modified'] == entry['modified'], 'Go record identity changed')
        severity = entry['current_severity']
        require(severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN')
                and entry['currently_blocking'] is (severity in ('HIGH', 'CRITICAL', 'UNKNOWN')),
                'Go record severity classification changed')
        all_records[entry['cve']] = entry['go_id']
        if entry['currently_blocking']:
            blocking[entry['cve']] = (entry['go_id'], entry['sha256'], severity)
    expected = {f['id']: (f['go_id'], f['record_sha256'], f['severity']) for f in policy['findings']}
    require(len(expected) == len(policy['findings']) and blocking == expected and blocking,
            'incomplete accepted Go record mapping')
    return {'refreshed_records': len(all_records), 'accepted_records': len(blocking)}


def evaluate(root, authority_path, authority_sha, compose, rendered, nginx_config, now):
    authority = checked(authority_path, authority_sha)
    validate_authority(authority, now)
    preflight = root / 'published-readiness-20261010'
    policy = checked(preflight / 'mariadb-30-disposition.proposed.json', PROPOSAL_SHA)
    # Some evidence files are JSON streams, not single JSON objects.
    for name, digest in policy['evidence_sha256'].items():
        require(hashlib.sha256(within(preflight, name).read_bytes()).hexdigest() == digest,
                'disposition evidence changed')
    records = validate_records(preflight, shared.load(preflight / 'go-record-refresh.json'), policy, now)
    recent(shared.load(preflight / 'applicability/execution.json')['checked_at'], now)
    manifest = (preflight / 'db-live-manifest.json').read_bytes()
    require('sha256:' + hashlib.sha256(manifest).hexdigest() == DB_REF.split('@')[1]
            and json.loads(manifest)['config']['digest'] == DB_CONFIG, 'DB registry leaf/config mismatch')
    index_raw = (preflight / 'db-live-index.json').read_bytes()
    require('sha256:' + hashlib.sha256(index_raw).hexdigest() == DB_INDEX, 'DB index changed')
    leaves = [m for m in json.loads(index_raw)['manifests'] if m.get('platform', {}).get('os') == 'linux'
              and m.get('platform', {}).get('architecture') == 'arm64']
    require(len(leaves) == 1 and leaves[0]['digest'] == DB_REF.split('@')[1], 'ambiguous/wrong ARM64 leaf')
    db = validate_db(shared.load(preflight / 'db-scan.json'),
                     checked(root / 'staging-preflight-20261007/noble-installed-inventory.json', DB_INVENTORY_SHA),
                     checked(preflight / 'db-scan-db.json', DB_METADATA_SHA), policy, now)
    config = validate_compose(compose, shared.load(rendered), nginx_config)
    return {'schema_version': 1, 'status': 'LOCAL_STAGING_CANDIDATE_WITH_ACCEPTED_DISPOSITION',
            'checked_at': now.isoformat(), 'authority_sha256': authority_sha, 'proposal_sha256': PROPOSAL_SHA,
            'components': {kind: component(root, kind, now) for kind in COMPONENTS},
            'db': {'image': DB_REF, **db, 'review_at': REVIEW_AT, 'expires_at': EXPIRES_AT},
            'go_record_coverage': records, 'configuration': config, 'staging_deployable': False, 'production': 'HOLD',
            'pending': ['Recheck PHP/Nginx/DB scans and host capacity before execution',
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
