#!/usr/bin/env python3
"""Bind tested ARM64 image, final digest scan and SBOM; never authorize deployment."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPOSITORY = "cahangeorge/LimeSurvey"
SOURCE = "https://github.com/" + REPOSITORY
IMAGE = "ghcr.io/cahangeorge/limesurvey"
UPSTREAM = "c5a2ac817396220e054efc3fd26b84cafb92b36f"
VERSION = "7.5.0+261001"
PLUGIN_TARGET = "var/www/html/application/core/plugins/TwoFactorAdminLogin/vendor/composer/installed.json"
ROOT_TARGET = "var/www/html/vendor/composer/installed.json"
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json")


class GateError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def preflight(branch, runs, sha, ref):
    require(ref == "refs/heads/main" and re.fullmatch(r"[0-9a-f]{40}", sha), "release requires main SHA")
    require(branch.get("protected") is True and branch["commit"]["sha"] == sha, "main changed or is unprotected")
    candidates = runs.get("workflow_runs")
    require(isinstance(candidates, list) and bool(candidates), "missing required CI run")
    # The newest push run for this SHA must pass; an older success cannot hide a failure.
    run = max(candidates, key=lambda item: item["id"])
    require(run.get("head_sha") == sha and run.get("head_branch") == "main"
            and run.get("event") == "push" and run.get("path") == ".github/workflows/release-gate.yml"
            and run.get("repository", {}).get("full_name") == REPOSITORY,
            "CI provenance mismatch")
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "required CI is not PASS")
    require(isinstance(run.get("run_attempt"), int) and run["run_attempt"] > 0, "missing CI attempt")
    return {key: run[key] for key in ("id", "run_attempt", "head_sha", "event", "path")}


def pairs(packages, name_key, version_key, composer=False, debian=False, alpine=False):
    require(isinstance(packages, list) and bool(packages), "missing package inventory")
    found = set()
    for item in packages:
        name, version = item[name_key], item[version_key]
        require(isinstance(name, str) and bool(name) and isinstance(version, str) and bool(version),
                "invalid package identity")
        if debian:
            epoch, release = item.get("Epoch", 0), item.get("Release", "")
            require(isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 0
                    and isinstance(release, str), "invalid Debian package version")
            version = (str(epoch) + ":" if epoch else "") + version + ("-" + release if release else "")
        if alpine:
            require(item.get("Epoch", 0) == 0 and item.get("Release", "") == "",
                    "APK version must include its exact release revision")
        found.add((name, version.removeprefix("v") if composer else version))
    return found


def supported_os(family, version):
    # Explicit allowlist, not all releases of a recognized package manager.
    patterns = {"debian": r"12(?:\.[0-9]+)?", "alpine": r"3\.24(?:\.[0-9]+)?"}
    require(isinstance(family, str) and family in patterns and isinstance(version, str)
            and re.fullmatch(patterns[family], version), "unsupported runtime OS/release")


def parse_os_release(raw):
    fields = {}
    for line in raw.splitlines():
        key, separator, value = line.strip().partition("=")
        if key not in ("ID", "VERSION_ID"):
            continue
        match = re.fullmatch(r'''(["']?)([A-Za-z0-9._-]+)\1''', value)
        require(separator and key not in fields and match is not None, "invalid runtime OS identity")
        fields[key] = match[2]
    require("ID" in fields and "VERSION_ID" in fields, "missing runtime OS identity")
    return fields["ID"], fields["VERSION_ID"]


def parse_apk_inventory(raw):
    packages, names = [], set()
    for record in raw.strip("\n").split("\n\n"):
        fields = {}
        for line in record.splitlines():
            if line[:2] not in ("P:", "V:"):
                continue  # APK file/ACL/dependency fields can repeat.
            key, value = line[0], line[2:]
            require(key not in fields and re.fullmatch(r"[^\s]+", value), "invalid APK package identity")
            fields[key] = value
        require("P" in fields and "V" in fields and fields["P"] not in names,
                "missing or duplicate APK package record")
        names.add(fields["P"])
        packages.append([fields["P"], fields["V"]])
    return packages


def check_db(db, now):
    require(db.get("Version") == 2, "invalid vulnerability DB")
    for field, limit in (("UpdatedAt", 48), ("DownloadedAt", 24)):
        stamp = datetime.fromisoformat(db[field].replace("Z", "+00:00"))
        require(stamp.tzinfo is not None and -300 <= (now - stamp).total_seconds() <= limit * 3600,
                "stale or future-dated vulnerability DB")


def validate_image(raw, digest, inspected, report, inventory, db, sbom, sha, now):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "invalid digest")
    require("sha256:" + hashlib.sha256(raw).hexdigest() == digest, "registry manifest digest mismatch")
    manifest = json.loads(raw)
    require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") in MANIFEST_TYPES
            and isinstance(manifest.get("layers"), list) and bool(manifest["layers"]),
            "expected single-platform image manifest")
    require(isinstance(inspected, list) and len(inspected) == 1, "ambiguous runtime image")
    image = inspected[0]
    image_id = image["Id"]
    ref = IMAGE + "@" + digest
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            and manifest["config"]["digest"] == image_id, "tested image config mismatch")
    require(image.get("Os") == "linux" and image.get("Architecture") == "arm64", "wrong runtime platform")
    require(ref in image.get("RepoDigests", []), "runtime image lacks final registry digest")
    labels = image["Config"]["Labels"]
    require(labels.get("org.opencontainers.image.source") == SOURCE
            and labels.get("org.opencontainers.image.revision") == sha
            and labels.get("io.omnestack.limesurvey.upstream-revision") == UPSTREAM
            and labels.get("org.opencontainers.image.version") == VERSION, "image source/version mismatch")
    require(report.get("SchemaVersion") == 2 and report.get("ArtifactName") == ref
            and report.get("ArtifactType") == "container_image"
            and report.get("Trivy", {}).get("Version") == "0.75.0", "wrong final scan identity/tool")
    metadata = report["Metadata"]
    require(metadata.get("ImageID") == image_id and ref in metadata.get("RepoDigests", []), "scanned image mismatch")
    require(metadata.get("ImageConfig", {}).get("architecture") == "arm64"
            and metadata.get("ImageConfig", {}).get("os") == "linux", "scanned platform mismatch")
    family, version = inventory.get("os_family"), inventory.get("os_version")
    supported_os(family, version)
    scanned_os = metadata.get("OS", {})
    supported_os(scanned_os.get("Family"), scanned_os.get("Name"))
    require(scanned_os.get("Family") == family and scanned_os.get("Eosl", False) is False,
            "runtime OS mismatch or EOL")
    # Debian's OS release says 12; Trivy can identify a point release (12.x).
    require(family == "debian" or scanned_os["Name"] == version, "runtime OS version mismatch")
    check_db(db, now)

    results = report.get("Results")
    require(isinstance(results, list) and bool(results), "missing final scan results")
    os_results = [item for item in results if item.get("Class") == "os-pkgs"]
    require(len(os_results) == 1 and os_results[0].get("Type") == family, "missing or ambiguous OS inventory")
    expected_os = pairs(inventory["os"], 0, 1)
    require(pairs(os_results[0].get("Packages"), "Name", "Version",
                  debian=family == "debian", alpine=family == "alpine") == expected_os,
            "incomplete installed OS coverage")
    expected_php = inventory["composer"]
    require(isinstance(expected_php, dict) and ROOT_TARGET in expected_php and PLUGIN_TARGET in expected_php,
            "missing upstream Composer inventories")
    composer_count = 0
    for target, packages in expected_php.items():
        matches = [item for item in results if item.get("Target") == target
                   and item.get("Class") == "lang-pkgs" and item.get("Type") == "composer-vendor"]
        require(len(matches) == 1, "missing installed Composer scan target")
        expected = pairs(packages, 0, 1, composer=True)
        require(pairs(matches[0].get("Packages"), "Name", "Version", composer=True) == expected,
                "incomplete installed Composer package/version coverage")
        composer_count += len(expected)
    all_purls = set()
    for result in results:
        packages = result.get("Packages")
        pairs(packages, "Name", "Version")
        for package in packages:
            purl = package.get("Identifier", {}).get("PURL")
            require(isinstance(purl, str) and purl.startswith("pkg:"), "missing scanned package PURL")
            all_purls.add(purl)
        findings = result.get("Vulnerabilities", [])
        require(isinstance(findings, list), "invalid vulnerability findings")
        for finding in findings:
            severity = finding.get("Severity")
            require(severity in ("LOW", "MEDIUM"), "HIGH/CRITICAL or unclassified finding blocks eligibility")
        require(not result.get("Secrets"), "image secret findings block eligibility")

    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.7", "unsupported SBOM")
    component = sbom["metadata"]["component"]
    require(component.get("type") == "container" and component.get("name") == ref
            and {"name": "aquasecurity:trivy:ImageID", "value": image_id} in component.get("properties", []),
            "SBOM image mismatch")
    components = sbom.get("components")
    require(isinstance(components, list), "missing SBOM inventory")
    sbom_purls = {item["purl"] for item in components if item.get("purl")}
    require(all_purls <= sbom_purls, "SBOM missing scanned package/version PURL")
    return {"os_packages": len(expected_os), "composer_packages": composer_count}


# Extract independently from PHP's installed metadata, not generated installed.json.
INVENTORY_PHP = r'''
$targets = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator('/var/www/html', FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    if ($file->getFilename() !== 'installed.php' || basename($file->getPath()) !== 'composer') continue;
    $data = require $file->getPathname();
    if (!isset($data['root'], $data['versions'])) throw new RuntimeException('Invalid Composer inventory');
    $packages = [];
    foreach ($data['versions'] as $name => $package) {
        if ($name === ($data['root']['name'] ?? '__root__')) continue;
        if (!isset($package['install_path']) && (isset($package['provided']) || isset($package['replaced']))) continue;
        $path = $package['install_path'] ?? ($file->getPath() . '/../' . $name);
        if (!is_dir($path) || empty($package['pretty_version'])) throw new RuntimeException('Missing package');
        $packages[] = [$name, $package['pretty_version']];
    }
    $targets[ltrim($file->getPath(), '/') . '/installed.json'] = $packages;
}
echo json_encode($targets, JSON_THROW_ON_ERROR);
'''


def extract_inventory(image):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "inventory requires tested config ID")
    def run(entrypoint, *args):
        return subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--entrypoint", entrypoint,
                                        image, *args], timeout=120, text=True)
    family, version = parse_os_release(run("cat", "/etc/os-release"))
    supported_os(family, version)
    if family == "alpine":
        os_packages = parse_apk_inventory(run("cat", "/lib/apk/db/installed"))
    else:
        rows = run("dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Package}\t${Version}\n")
        os_packages = []
        for row in rows.splitlines():
            if row.startswith("ii "):
                fields = row.split("\t")
                require(len(fields) == 3, "invalid Debian package record")
                os_packages.append(fields[1:])
        pairs(os_packages, 0, 1)
    return {"os_family": family, "os_version": version, "os": os_packages,
            "composer": json.loads(run("php", "-r", INVENTORY_PHP)),
            "php_version": run("php", "-r", "echo PHP_VERSION;").strip()}


def load(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pre = commands.add_parser("preflight")
    pre.add_argument("branch", type=Path)
    pre.add_argument("runs", type=Path)
    pre.add_argument("sha")
    pre.add_argument("ref")
    inventory = commands.add_parser("inventory")
    inventory.add_argument("image")
    release = commands.add_parser("manifest")
    release.add_argument("directory", type=Path)
    release.add_argument("digest")
    release.add_argument("sha")
    release.add_argument("run_id", type=int)
    release.add_argument("attempt", type=int)
    args = parser.parse_args()
    try:
        if args.command == "preflight":
            result = preflight(load(args.branch), load(args.runs), args.sha, args.ref)
        elif args.command == "inventory":
            result = extract_inventory(args.image)
        else:
            root = args.directory
            require(args.run_id > 0 and args.attempt > 0, "invalid release run identity")
            require(re.fullmatch(r"[0-9a-f]{40}", args.sha), "invalid source SHA")
            inspected, report, inventory, db, sbom = (load(root / name) for name in (
                "image.json", "scan.json", "inventory.json", "db.json", "sbom.cdx.json"))
            counts = validate_image((root / "registry-manifest.json").read_bytes(), args.digest,
                                    inspected, report, inventory, db, sbom, args.sha, datetime.now(timezone.utc))
            ci = load(root / "ci.json")
            require(ci.get("head_sha") == args.sha and ci.get("event") == "push"
                    and ci.get("path") == ".github/workflows/release-gate.yml", "manifest CI mismatch")
            files = ("registry-manifest.json", "image.json", "inventory.json", "scan.json", "db.json", "sbom.cdx.json", "ci.json")
            result = {"schema_version": 1, "status": "ARTIFACT_VERIFIED", "repository": REPOSITORY,
                      "source_commit": args.sha, "config_commit": args.sha,
                      "image": IMAGE + "@" + args.digest, "digest": args.digest,
                      "image_config_digest": inspected[0]["Id"], "platform": "linux/arm64",
                      "upstream": {"version": VERSION, "commit": UPSTREAM},
                      "ci": ci, "release_run": {"id": args.run_id, "attempt": args.attempt,
                      "url": f"{SOURCE}/actions/runs/{args.run_id}"},
                      "scan": {"status": "PASS", "tool": "Trivy 0.75.0", **counts},
                      "evidence_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files},
                      "staging": {"status": "PENDING"}, "production": {"status": "HOLD"},
                      "configuration_schema": {"status": "REVIEW_REQUIRED"},
                      "migrations": {"status": "REVIEW_REQUIRED"}, "previous_promoted_digest": None,
                      "coverage_limits": ["Source-built PHP interpreter and LimeSurvey application code are outside Composer/OS CVE inventory",
                                          "Bundled non-Composer assets need separate upgrade/security review"]}
            (root / "release.json").write_text(json.dumps(result, indent=2) + "\n")
            print("release_artifact=PASS; staging=PENDING; production=HOLD")
            return 0
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, GateError) else "missing, malformed or failed evidence"
        print(f"release_artifact=HOLD: {reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
