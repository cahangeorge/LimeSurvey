#!/usr/bin/env python3
"""Reject unsafe Trivy reports, missing Composer coverage, and stale databases."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


class GateError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def check(report, lock, metadata, now):
    require(all(isinstance(item, dict) for item in (report, lock, metadata)), "invalid document")
    require(report.get("SchemaVersion") == 2, "unsupported report schema")
    require(report.get("ArtifactName") == "composer.lock", "wrong scanned artifact")
    require(report.get("ArtifactType") == "filesystem", "wrong scan type")
    require(metadata.get("Version") == 2, "missing vulnerability DB metadata")
    for field, max_hours in (("UpdatedAt", 48), ("DownloadedAt", 24)):
        try:
            timestamp = datetime.fromisoformat(metadata[field].replace("Z", "+00:00"))
            require(timestamp.tzinfo is not None, "DB timestamp lacks timezone")
            age = (now - timestamp).total_seconds()
        except (KeyError, TypeError, AttributeError, ValueError) as error:
            raise GateError("invalid DB timestamp") from error
        require(-300 <= age <= max_hours * 3600, "vulnerability DB is stale or future-dated")

    expected = set()
    for field in ("packages", "packages-dev"):
        packages = lock.get(field)
        require(isinstance(packages, list), "invalid Composer lockfile")
        for package in packages:
            require(isinstance(package, dict), "invalid locked package")
            name, version = package.get("name"), package.get("version")
            require(isinstance(name, str) and bool(name) and isinstance(version, str) and bool(version),
                    "missing locked package identity")
            expected.add((name, version))
    require(bool(expected), "empty lockfile cannot prove coverage")

    results = report.get("Results")
    require(isinstance(results, list) and len(results) == 1, "missing or ambiguous scan target")
    result = results[0]
    require(isinstance(result, dict), "invalid scan result")
    require(result.get("Target") == "composer.lock" and result.get("Type") == "composer"
            and result.get("Class") == "lang-pkgs", "Composer lockfile was not scanned")
    packages = result.get("Packages")
    require(isinstance(packages, list), "missing package inventory")
    scanned = set()
    for package in packages:
        require(isinstance(package, dict), "invalid package inventory")
        name, version = package.get("Name"), package.get("Version")
        require(isinstance(name, str) and isinstance(version, str), "invalid scanned package identity")
        scanned.add((name, version))
    require(scanned == expected, "scan does not cover every locked package and version")

    findings = result.get("Vulnerabilities", [])
    require(isinstance(findings, list), "invalid vulnerability findings")
    for finding in findings:
        require(isinstance(finding, dict), "invalid vulnerability finding")
        severity = finding.get("Severity")
        require(severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"), "unclassified finding needs triage")
        require(severity not in ("HIGH", "CRITICAL"), "HIGH/CRITICAL vulnerability blocks release")
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("lockfile", type=Path)
    parser.add_argument("db_metadata", type=Path)
    args = parser.parse_args()
    try:
        count = check(*(json.loads(path.read_text()) for path in
                        (args.report, args.lockfile, args.db_metadata)), datetime.now(timezone.utc))
    except (OSError, ValueError, TypeError) as error:
        # No report contents or dependency values are included in failure logs.
        reason = str(error) if isinstance(error, GateError) else "missing or malformed report/input"
        print(f"dependency_gate=HOLD: {reason}", file=sys.stderr)
        return 1
    print(f"dependency_gate=PASS: {count} locked packages inventoried (including dev dependencies)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
