#!/usr/bin/env python3
"""Fail-closed Nginx companion evidence; no deployment authorization."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import parse_qsl, unquote, urlsplit

_spec = importlib.util.spec_from_file_location('release_artifact', Path(__file__).with_name('release-artifact.py'))
shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shared)
require = shared.require
IMAGE = 'ghcr.io/cahangeorge/limesurvey-nginx'
VERSION = '1.30.5-alpine3.24.2'
PATCHES = {'libexpat': '2.8.5-r0', 'libpng': '1.6.59-r0', 'pcre2': '10.49-r0', 'tiff': '4.7.2-r0'}
FPM_REF = shared.IMAGE + '@sha256:4193d1c9bef626c675381fe2bad07b400bcf5cce56e373c221babae2ce9d3510'
FPM_ID = 'sha256:ecad9df832a2f9e20585922ece061d2527f117a9436c8271ca27efe33c1fb4da'
FPM_SHA = '58de3e047274976775a726fe4b21d879ba7a7844'


def config_id(value):
    require(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value), 'invalid config/digest identity')
    return value


def registry_image(raw, digest, inspected, ref):
    config_id(digest)
    require('sha256:' + hashlib.sha256(raw).hexdigest() == digest, 'raw registry manifest hash mismatch')
    manifest = json.loads(raw)
    require(manifest.get('schemaVersion') == 2 and manifest.get('mediaType') in shared.MANIFEST_TYPES
            and isinstance(manifest.get('layers'), list) and manifest['layers'], 'expected single-platform manifest')
    require(isinstance(inspected, list) and len(inspected) == 1, 'ambiguous inspected image')
    image = inspected[0]
    config_id(image['Id'])
    require(manifest['config']['digest'] == image['Id'], 'manifest config mismatch')
    require(image.get('Os') == 'linux' and image.get('Architecture') == 'arm64', 'wrong runtime platform')
    require(ref in image.get('RepoDigests', []), 'missing exact registry reference')
    return image


def validate_fpm(raw, inspected):
    image = registry_image(raw, FPM_REF.split('@')[1], inspected, FPM_REF)
    labels = image['Config']['Labels']
    require(image['Id'] == FPM_ID and labels.get('org.opencontainers.image.source') == shared.SOURCE
            and labels.get('org.opencontainers.image.revision') == FPM_SHA, 'unapproved FPM artifact')
    return {'reference': FPM_REF, 'config_id': FPM_ID, 'source_commit': FPM_SHA,
            'release_run': {'id': 37186347292, 'attempt': 1}}


def validate_candidate_image(inspected, sha):
    require(re.fullmatch(r'[0-9a-f]{40}', sha), 'invalid source SHA')
    require(isinstance(inspected, list) and len(inspected) == 1, 'ambiguous candidate')
    image = inspected[0]
    config_id(image['Id'])
    require(image.get('Os') == 'linux' and image.get('Architecture') == 'arm64', 'wrong candidate platform')
    labels = image['Config']['Labels']
    require(labels.get('org.opencontainers.image.source') == shared.SOURCE
            and labels.get('org.opencontainers.image.revision') == sha
            and labels.get('org.opencontainers.image.version') == VERSION
            and labels.get('io.omnestack.limesurvey.component') == 'nginx', 'Nginx provenance mismatch')
    return image['Id']


def unique_pairs(packages, name_key, version_key):
    require(isinstance(packages, list) and packages, 'missing package inventory')
    pairs, names = set(), set()
    for item in packages:
        name, version = item[name_key], item[version_key]
        require(isinstance(name, str) and name and isinstance(version, str) and version and name not in names,
                'invalid or duplicate package identity')
        names.add(name)
        pairs.add((name, version))
    return pairs


def apk_purl(purl, name, version):
    require(isinstance(purl, str) and not re.search(r'%(?![0-9a-fA-F]{2})', purl)
            and '#' not in purl, 'malformed APK PURL')
    parsed = urlsplit(purl)
    package, separator, release = parsed.path.removeprefix('apk/alpine/').rpartition('@')
    require(parsed.scheme == 'pkg' and not parsed.netloc and parsed.path.startswith('apk/alpine/')
            and separator and '/' not in package and unquote(package, errors='strict') == name
            and unquote(release, errors='strict') == version, 'APK PURL package identity mismatch')
    qualifiers = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    require(len(qualifiers) == 2 and dict(qualifiers) == {'arch': 'aarch64', 'distro': '3.24.2'},
            'APK PURL qualifiers mismatch or duplicate')
    return purl


def validate_scan(report, inventory, db, image_id, artifact, now, ref=None):
    config_id(image_id)
    require(report.get('SchemaVersion') == 2 and report.get('ArtifactName') == artifact
            and report.get('ArtifactType') == 'container_image'
            and report.get('Trivy', {}).get('Version') == '0.75.0', 'wrong scan artifact/tool')
    metadata = report['Metadata']
    require(metadata.get('ImageID') == image_id, 'scan config mismatch')
    if ref:
        require(ref in metadata.get('RepoDigests', []), 'scan registry digest mismatch')
    else:
        require(report.get('ArtifactID') == image_id, 'export scan identity mismatch')
    require(metadata.get('ImageConfig', {}).get('architecture') == 'arm64'
            and metadata.get('ImageConfig', {}).get('os') == 'linux', 'wrong scanned platform')
    os = metadata['OS']
    require(inventory.get('os_family') == 'alpine' and inventory.get('os_version') == '3.24.2'
            and os.get('Family') == 'alpine' and os.get('Name') == '3.24.2'
            and os.get('Eosl', False) is False and os.get('EOSL', False) is False, 'unsupported OS/version or EOL')
    shared.check_db(db, now)
    expected = unique_pairs(inventory['os'], 0, 1)
    require(set(PATCHES.items()) <= expected, 'missing patched APK versions')
    results = report.get('Results')
    require(isinstance(results, list) and results, 'empty scan results')
    os_results = [r for r in results if r.get('Class') == 'os-pkgs']
    require(len(results) == 1 and len(os_results) == 1 and os_results[0].get('Type') == 'alpine', 'missing/ambiguous APK scan')
    require(os_results[0].get('Target') == artifact + ' (alpine 3.24.2)', 'scan APK target mismatch')
    require(unique_pairs(os_results[0].get('Packages'), 'Name', 'Version') == expected, 'incomplete APK coverage')
    purls = set()
    for result in results:
        unique_pairs(result.get('Packages'), 'Name', 'Version')
        for package in result['Packages']:
            require(package.get('Epoch', 0) == 0 and package.get('Release', '') == '', 'split APK version')
            purl = package.get('Identifier', {}).get('PURL')
            apk_purl(purl, package['Name'], package['Version'])
            require(purl not in purls, 'duplicate package PURL')
            purls.add(purl)
        findings = result.get('Vulnerabilities', [])
        require(isinstance(findings, list), 'malformed findings')
        for finding in findings:
            require(finding.get('Severity') in ('LOW', 'MEDIUM'), 'blocking or malformed severity')
        require(not result.get('Secrets'), 'secret findings block release')
    return purls


def validate_image(raw, digest, inspected, report, inventory, db, sbom, sha, now):
    ref = IMAGE + '@' + digest
    image = registry_image(raw, digest, inspected, ref)
    image_id = validate_candidate_image(inspected, sha)
    purls = validate_scan(report, inventory, db, image_id, ref, now, ref)
    scanned_config = report['Metadata']['ImageConfig']
    for key, inspected_key in (('created', 'Created'),):
        if key in scanned_config:
            require(scanned_config[key] == image.get(inspected_key), 'scan config metadata mismatch')
    if 'rootfs' in scanned_config:
        require(scanned_config['rootfs'].get('diff_ids') == image.get('RootFS', {}).get('Layers'),
                'scan rootfs differs from inspected config')
    if 'config' in scanned_config and 'Labels' in scanned_config['config']:
        require(scanned_config['config']['Labels'] == image['Config']['Labels'], 'scan labels differ from inspected config')
    require(sbom.get('bomFormat') == 'CycloneDX' and sbom.get('specVersion') == '1.7', 'unsupported SBOM')
    component = sbom['metadata']['component']
    require(component.get('type') == 'container' and component.get('name') == ref
            and {'name': 'aquasecurity:trivy:ImageID', 'value': image['Id']} in component.get('properties', []),
            'SBOM image identity mismatch')
    components = sbom.get('components')
    require(isinstance(components, list) and components, 'empty SBOM')
    covered = set()
    for component in components:
        if component.get('type') == 'operating-system':
            require(component.get('name') == 'alpine' and component.get('version') == '3.24.2'
                    and not component.get('purl'), 'SBOM OS component mismatch')
            continue
        require(component.get('type') == 'library', 'SBOM package component type mismatch')
        purl = apk_purl(component.get('purl'), component.get('name'), component.get('version'))
        require(component.get('bom-ref') == purl and purl not in covered, 'SBOM package reference mismatch or duplicate')
        covered.add(purl)
    require(purls == covered, 'SBOM APK coverage mismatch')
    return {'os_packages': len(inventory['os'])}


def extract_inventory(image):
    config_id(image)
    def run(path):
        return subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat',
                                        image, path], text=True, timeout=120)
    family, version = shared.parse_os_release(run('/etc/os-release'))
    require((family, version) == ('alpine', '3.24.2'), 'wrong runtime OS')
    return {'os_family': family, 'os_version': version, 'os': shared.parse_apk_inventory(run('/lib/apk/db/installed'))}


def candidate(root, sha, now):
    tested = shared.load(root / 'tested.json')
    image_id = validate_candidate_image(shared.load(root / 'candidate-image.json'), sha)
    require(tested.get('nginx_config_id') == image_id and tested.get('fpm_config_id') == FPM_ID,
            'tested config identity mismatch')
    require(isinstance(tested.get('artifact'), str) and tested['artifact'].startswith('/'), 'missing exported artifact path')
    validate_fpm((root / 'fpm-manifest.json').read_bytes(), shared.load(root / 'fpm-image.json'))
    smoke = (root / 'smoke.log').read_text().splitlines()
    require('NGINX_IMAGE=' + image_id in smoke and 'FPM_IMAGE=' + FPM_ID in smoke
            and 'PASS: health, config, static, FastCGI HTTPS/path/proxy, 7 protected paths, PHP deny' in smoke,
            'missing successful exact-ID smoke/cleanup')
    validate_scan(shared.load(root / 'candidate-scan.json'), shared.load(root / 'inventory.json'),
                  shared.load(root / 'candidate-db.json'), image_id, tested['artifact'], now)
    return tested


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    pre = commands.add_parser('preflight')
    pre.add_argument('branch', type=Path); pre.add_argument('runs', type=Path)
    pre.add_argument('sha'); pre.add_argument('ref')
    inv = commands.add_parser('inventory'); inv.add_argument('image')
    fpm = commands.add_parser('fpm'); fpm.add_argument('directory', type=Path)
    can = commands.add_parser('candidate'); can.add_argument('directory', type=Path); can.add_argument('sha')
    final = commands.add_parser('manifest'); final.add_argument('directory', type=Path)
    final.add_argument('digest'); final.add_argument('sha'); final.add_argument('run_id', type=int); final.add_argument('attempt', type=int)
    args = parser.parse_args()
    try:
        now = datetime.now(timezone.utc)
        if args.command == 'manifest':
            # Reused directories must never retain a prior apparently valid output after failure.
            (args.directory / 'release.json').unlink(missing_ok=True)
        if args.command == 'preflight':
            result = shared.preflight(shared.load(args.branch), shared.load(args.runs), args.sha, args.ref)
        elif args.command == 'inventory':
            result = extract_inventory(args.image)
        elif args.command == 'fpm':
            result = validate_fpm((args.directory / 'fpm-manifest.json').read_bytes(), shared.load(args.directory / 'fpm-image.json'))
        elif args.command == 'candidate':
            result = candidate(args.directory, args.sha, now)
        else:
            root = args.directory
            require(args.run_id > 0 and args.attempt > 0, 'invalid release run identity')
            tested = candidate(root, args.sha, now)
            inspected = shared.load(root / 'image.json')
            require(inspected[0]['Id'] == tested['nginx_config_id'], 'published config differs from tested config')
            counts = validate_image((root / 'registry-manifest.json').read_bytes(), args.digest, inspected,
                                    shared.load(root / 'scan.json'), shared.load(root / 'inventory.json'),
                                    shared.load(root / 'db.json'), shared.load(root / 'sbom.cdx.json'), args.sha, now)
            ci = shared.preflight(shared.load(root / 'branch.json'), shared.load(root / 'runs.json'), args.sha, 'refs/heads/main')
            require(shared.load(root / 'ci.json') == ci, 'CI evidence mismatch')
            files = ('registry-manifest.json', 'image.json', 'inventory.json', 'scan.json', 'db.json', 'sbom.cdx.json',
                     'branch.json', 'runs.json', 'ci.json', 'tested.json', 'smoke.log', 'fpm-manifest.json', 'fpm-image.json',
                     'candidate-image.json', 'candidate-scan.json', 'candidate-db.json')
            result = {'schema_version': 1, 'status': 'COMPANION_ARTIFACT_VERIFIED', 'component': 'nginx',
                      'repository': shared.REPOSITORY, 'source_commit': args.sha, 'image': IMAGE + '@' + args.digest,
                      'registry_manifest_digest': args.digest, 'image_config_digest': inspected[0]['Id'],
                      'platform': 'linux/arm64', 'tested': tested, 'fpm': validate_fpm((root / 'fpm-manifest.json').read_bytes(), shared.load(root / 'fpm-image.json')),
                      'ci': ci, 'release_run': {'id': args.run_id, 'attempt': args.attempt},
                      'scan': {'status': 'PASS', 'tool': 'Trivy 0.75.0', **counts},
                      'evidence_sha256': {n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in files},
                      'staging': {'status': 'PENDING'}, 'production': {'status': 'HOLD'},
                      'coverage_limits': ['Synthetic proxy smoke does not establish LimeSurvey or database acceptance',
                                          'Separate staging configuration, MariaDB and deployment gates remain required']}
            (root / 'release.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, shared.GateError) else 'missing, malformed or failed evidence'
        print('nginx_release=HOLD: ' + reason, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
