#!/usr/bin/env python3
"""Admit a trusted fresh three-image bundle; never authorize deployment."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


nginx = module('nginx-release')
mariadb = module('mariadb-release')
signing = module('sign-release')
shared = nginx.shared
require = shared.require
COMPONENTS = {'php', 'nginx', 'mariadb'}
SIGNATURE_FILES = {'cosign-signature.json', 'cosign-provenance.json', 'cosign-sbom.json'}
NGINX_EVIDENCE = {'branch.json', 'runs.json', 'tested.json', 'smoke.log', 'fpm-manifest.json',
                  'fpm-image.json', 'candidate-image.json', 'candidate-scan.json', 'candidate-db.json'}


def timestamp(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(stamp.tzinfo is not None, 'timestamp requires timezone')
    return stamp


def recent(value, now):
    require(-300 <= (now - timestamp(value)).total_seconds() <= 86400,
            'stale or future-dated scan/database')


def checked(path, digest):
    require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest), 'invalid evidence hash')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, 'evidence hash mismatch')
    return json.loads(raw)


def evidence_path(root, name):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name),
            'unsafe evidence name')
    path = root / name
    require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()), 'evidence path escape')
    return path


def validate_artifact(root, kind, expected, sha, now):
    load = lambda name: shared.load(root / name)
    release = load('release.json')
    ctx = signing.context(root, kind, sha, expected['release_run']['id'], expected['release_run']['attempt'])
    require(ctx['image'] == expected['image'] and release['image_config_digest'] == expected['image_config_digest'],
            'expected image/config mismatch')
    images = load('image.json')
    require(isinstance(images, list) and len(images) == 1
            and images[0].get('Id') == expected['image_config_digest'], 'expected inspected config mismatch')
    require(release['evidence_sha256'] == expected['evidence_sha256'], 'expected raw evidence mismatch')
    require(load('ci.json') == release['ci'], 'CI receipt mismatch')
    for scan_name, db_name in [('scan.json', 'db.json')] + (
            [('candidate-scan.json', 'candidate-db.json')] if kind != 'php' else []):
        recent(load(scan_name)['CreatedAt'], now)
        db = load(db_name)
        for field in ('UpdatedAt', 'DownloadedAt'):
            recent(db[field], now)
        # Strictly prohibit hidden findings even if a component validator does not use this field.
        for result in load(scan_name)['Results']:
            require(not result.get('Misconfigurations') and not result.get('Secrets'), 'secret/config findings')
    raw = (root / 'registry-manifest.json').read_bytes()
    if kind == 'php':
        require(release.get('config_commit') == sha
                and release.get('upstream') == {'version': shared.VERSION, 'commit': shared.UPSTREAM},
                'wrong application build source/upstream policy')
        shared.validate_image(raw, ctx['digest'], load('image.json'), load('scan.json'),
                              load('inventory.json'), load('db.json'), load('sbom.cdx.json'), sha, now)
    elif kind == 'nginx':
        require(NGINX_EVIDENCE <= release['evidence_sha256'].keys(), 'missing companion evidence')
        nginx.candidate(root, sha, now)
        nginx.validate_image(raw, ctx['digest'], load('image.json'), load('scan.json'),
                             load('inventory.json'), load('db.json'), load('sbom.cdx.json'), sha, now)
        require(shared.preflight(load('branch.json'), load('runs.json'), sha, 'refs/heads/main') == load('ci.json'),
                'companion CI provenance mismatch')
    else:
        image, inventory = mariadb.candidate(root, sha, now)
        registry = json.loads(raw)
        require(registry.get('schemaVersion') == 2 and registry.get('mediaType') in shared.MANIFEST_TYPES
                and registry.get('layers') and registry['config']['digest'] == image['Id'], 'registry config mismatch')
        final = mariadb.validate_candidate_image(load('image.json'), sha)
        require(final['Id'] == image['Id'] and ctx['image'] in final.get('RepoDigests', []), 'published/tested identity mismatch')
        require(load('final-inventory.json') == inventory, 'published inventory changed')
        purls = mariadb.validate_scan(load('scan.json'), inventory, load('db.json'), image['Id'], ctx['image'], now, ctx['image'])
        mariadb.validate_sbom(load('sbom.cdx.json'), purls, image['Id'], ctx['image'], inventory['gosu'])
        require(shared.preflight(load('branch.json'), load('runs.json'), sha, 'refs/heads/main') == load('ci.json'),
                'database CI provenance mismatch')
    return ctx


def component(expected, kind, sha, now):
    root = Path(expected['evidence_directory'])
    require(root.is_absolute() and root.is_dir(), 'expected absolute evidence directory')
    release = checked(root / 'release.json', expected['release_sha256'])
    hashes = expected['evidence_sha256']
    require(isinstance(hashes, dict) and hashes == release['evidence_sha256']
            and signing.REQUIRED_EVIDENCE <= hashes.keys(), 'missing/substituted raw evidence')
    names = {'release.json', 'signing.json'} | SIGNATURE_FILES | hashes.keys()
    for name in names:
        evidence_path(root, name)
    # Copy only pinned inputs; validators and online verifier never write original receipts.
    with tempfile.TemporaryDirectory(prefix='limesurvey-admission-') as directory:
        owned = Path(directory)
        for name in names:
            shutil.copyfile(root / name, owned / name)
        checked(owned / 'release.json', expected['release_sha256'])
        receipt = checked(owned / 'signing.json', expected['signing_sha256'])
        ctx = validate_artifact(owned, kind, expected, sha, now)
        require(receipt.get('schema_version') == 1 and receipt.get('status') == 'SIGNATURES_VERIFIED'
                and receipt.get('image') == ctx['image'] and receipt.get('source_commit') == sha
                and receipt.get('identity') == ctx['identity'] and receipt.get('issuer') == signing.ISSUER
                and receipt.get('release_run') == expected['release_run']
                and receipt.get('release_sha256') == expected['release_sha256']
                and isinstance(receipt.get('verification_sha256'), dict)
                and set(receipt['verification_sha256']) == SIGNATURE_FILES, 'missing/wrong signing receipt')
        for name, digest in receipt['verification_sha256'].items():
            require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
                    and hashlib.sha256((owned / name).read_bytes()).hexdigest() == digest,
                    'archived verifier output hash mismatch')
        verified = signing.verify(owned, kind, sha, expected['release_run']['id'], expected['release_run']['attempt'])
        require(verified.get('status') == 'SIGNATURES_VERIFIED' and verified.get('image') == ctx['image']
                and verified.get('source_commit') == sha and verified.get('release_run') == expected['release_run']
                and verified.get('release_sha256') == expected['release_sha256'], 'online signature verification failed')
        return {'image': ctx['image'], 'image_config_digest': expected['image_config_digest'],
                'source_commit': sha, 'release_run': expected['release_run'],
                'release_sha256': expected['release_sha256'], 'scan': 'PASS', 'signatures': 'PASS',
                'coverage_limits': release.get('coverage_limits', [])}


def evaluate(expected_bundle_path, expected_bundle_sha256, now):
    bundle = checked(expected_bundle_path, expected_bundle_sha256)
    require(bundle.get('schema_version') == 1 and bundle.get('upstream_commit') == shared.UPSTREAM,
            'wrong bundle/security policy')
    sha = bundle['source_commit']
    require(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha), 'invalid artifact build source')
    require(isinstance(bundle.get('components'), dict) and set(bundle['components']) == COMPONENTS,
            'expected exactly PHP/Nginx/MariaDB')
    admitted = {kind: component(bundle['components'][kind], kind, sha, now) for kind in sorted(COMPONENTS)}
    return {'schema_version': 1, 'status': 'ARTIFACT_BUNDLE_ADMITTED', 'checked_at': now.isoformat(),
            'expected_bundle_sha256': expected_bundle_sha256, 'source_commit': sha, 'upstream_commit': shared.UPSTREAM,
            'components': admitted, 'staging_deployable': False, 'production': 'HOLD',
            'pending': ['Selected-triple runtime and configuration acceptance',
                        'Paired backup/isolated restore, migration, promotion and rollback acceptance']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-bundle', required=True, type=Path)
    parser.add_argument('--expected-bundle-sha256', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(evaluate(args.expected_bundle, args.expected_bundle_sha256, datetime.now(timezone.utc)), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        print('staging_release=HOLD: missing, changed, stale or unverified evidence', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
