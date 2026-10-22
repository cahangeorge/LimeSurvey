#!/usr/bin/env python3
"""Private, ID-only anonymous-response retention. Dry-run unless --apply."""
import argparse
import base64
import binascii
import csv
import fcntl
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import urllib.parse
import urllib.request

RETENTION = 365 * 86400
MARGIN = 3600
MAX_GAP = 3300
MAX_IDS = 5000
MAX_BYTES = 2 * 1024 * 1024


class RetentionError(Exception):
    pass


def require(ok, code):
    if not ok:
        raise RetentionError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_key')
        result[key] = value
    return result


def private(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.getuid(), 'unsafe_private_file')
    require(path.parent.stat().st_uid == os.getuid()
            and stat.S_IMODE(path.parent.stat().st_mode) == 0o700, 'unsafe_directory')


def read_json(path):
    private(path)
    with path.open('rb') as source:
        raw = source.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, 'oversized_file')
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise RetentionError('invalid_json') from None


def save(path, data):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.retention-')
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(data, out, sort_keys=True, separators=(',', ':'))
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def valid_id(value):
    return isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,9}', value) is not None


def parse_ids(encoded):
    require(isinstance(encoded, str) and len(encoded) <= MAX_BYTES, 'invalid_export')
    try:
        raw = base64.b64decode(encoded, validate=True).decode('utf-8-sig')
        rows = list(csv.reader(io.StringIO(raw, newline=''), strict=True))
    except (ValueError, UnicodeError, binascii.Error, csv.Error):
        raise RetentionError('invalid_export') from None
    # The pinned CSV exporter emits one terminal empty record after its CR/LF.
    # Remove exactly that structural record; internal or repeated blanks fail below.
    if rows and rows[-1] == []:
        rows.pop()
    require(bool(rows) and rows[0] == ['id'] and len(rows) <= MAX_IDS + 1, 'invalid_export')
    ids = set()
    for row in rows[1:]:
        require(len(row) == 1 and valid_id(row[0]) and row[0] not in ids, 'invalid_export')
        ids.add(row[0])
    return ids


def surveys(config):
    values = config.get('surveys')
    require(isinstance(values, list) and len(values) == 2, 'invalid_surveys')
    result = {}
    for survey in values:
        require(isinstance(survey, dict) and set(survey) == {'id', 'language'}, 'invalid_surveys')
        sid, lang = survey['id'], survey['language']
        require(type(sid) is int and valid_id(str(sid)) and str(sid) not in result
                and isinstance(lang, str) and re.fullmatch(r'[a-z]{2}(?:-[A-Za-z]{2,4})?', lang), 'invalid_surveys')
        result[str(sid)] = lang
    return result


def deleted(result, rid):
    return (result == {rid: 'deleted'}
            or result == {'status': 'Response Id not found', 'error_code': 'ERR_NOT_FOUND'})


def run(config, path, api, now, *, initialize=False, apply=False):
    allowed = surveys(config)
    require(type(now) is int and now > 0, 'invalid_clock')
    properties = {}
    for sid in allowed:
        props = api('get_survey_properties', int(sid), ['active', 'anonymized', 'datestamp'])
        require(isinstance(props, dict) and props.get('active') in ('Y', 'N')
                and props.get('anonymized') == 'Y' and props.get('datestamp') == 'N', 'privacy_settings_changed')
        properties[sid] = props
    if initialize:
        require(not path.exists() and not path.is_symlink(), 'state_already_exists')
        for sid in allowed:
            require(properties[sid]['active'] == 'N', 'initialization_requires_inactive')
            summary = api('get_summary', int(sid), 'full_responses')
            require(type(summary) in (str, int) and str(summary) == '0'
                    or summary == {'status': 'No available data', 'error_code': 'ERR_NO_DATA'},
                    'initialization_requires_empty')
        data = {'version': 1, 'last_scan': now, 'surveys': {
            sid: {'language': lang, 'ids': {}} for sid, lang in allowed.items()}}
        if apply:
            save(path, data)
        return {'initialized': apply, 'due': 0, 'deleted': 0}
    require(path.exists(), 'missing_state')
    data = read_json(path)
    require(isinstance(data, dict) and set(data) == {'version', 'last_scan', 'surveys'}
            and type(data['version']) is int and data['version'] == 1 and type(data['last_scan']) is int
            and isinstance(data['surveys'], dict) and set(data['surveys']) == set(allowed), 'invalid_state')
    prior = data['last_scan']
    require(0 <= now - prior <= MAX_GAP, 'scan_gap_or_clock_error')
    for sid, lang in allowed.items():
        cohort = data['surveys'][sid]
        require(isinstance(cohort, dict) and set(cohort) == {'language', 'ids'}
                and cohort['language'] == lang and isinstance(cohort['ids'], dict)
                and len(cohort['ids']) <= MAX_IDS, 'invalid_state')
        for rid, lower in cohort['ids'].items():
            require(valid_id(rid) and type(lower) is int and 0 < lower <= prior, 'invalid_state')
    # Validate every export before deleting anything. Never request response content.
    observed = {}
    for sid, lang in allowed.items():
        exported = api('export_responses', int(sid), 'csv', lang,
                       'all', 'code', 'short', None, None, ['id'])
        if (exported == {'status': 'No Data, survey table does not exist.',
                         'error_code': 'ERR_NO_RESPONSE_TABLE'}
                and properties[sid]['active'] == 'N'
                and not data['surveys'][sid]['ids']):
            observed[sid] = set()
        elif (exported == {'status': 'No Data, could not get max id.',
                           'error_code': 'ERR_NO_DATA'}
              and properties[sid]['active'] == 'Y'):
            # A genuinely empty active table also reconciles an interrupted last deletion.
            observed[sid] = set()
        else:
            observed[sid] = parse_ids(exported)
    due = []
    for sid in allowed:
        ids = data['surveys'][sid]['ids']
        for rid in list(ids):
            if rid not in observed[sid]:
                del ids[rid]
        for rid in observed[sid]:
            ids.setdefault(rid, prior)
            if now >= ids[rid] + RETENTION - MARGIN:
                due.append((sid, rid))
    count = 0
    if apply:
        # Persist discoveries before mutation; interrupted deletions retry safely.
        save(path, data)
        for sid, rid in due:
            require(deleted(api('delete_response', int(sid), int(rid)), rid), 'deletion_failed')
            del data['surveys'][sid]['ids'][rid]
            save(path, data)
            count += 1
        data['last_scan'] = now  # Start bound, never end-of-export time.
        save(path, data)
    return {'initialized': False, 'due': len(due), 'deleted': count}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RetentionError('rpc_redirect')


class RPC:
    def __init__(self, config):
        parsed = urllib.parse.urlsplit(config['endpoint'])
        require(parsed.scheme == 'http' and parsed.hostname is not None
                and ipaddress.ip_address(parsed.hostname).is_loopback
                and parsed.username is None and parsed.password is None
                and parsed.query in ('', 'r=admin/remotecontrol')
                and not parsed.fragment and parsed.path.startswith('/'), 'unsafe_endpoint')
        self.url = config['endpoint']
        self.deadline = time.monotonic() + 180
        self.calls = 0
        self.key = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.key = self.request('get_session_key', [config['username'], config['password']])
        require(isinstance(self.key, str) and 10 <= len(self.key) <= 256, 'authentication_failed')

    def request(self, method, params):
        self.calls += 1
        remaining = self.deadline - time.monotonic()
        require(self.calls <= 1000 and remaining > 0, 'rpc_budget_exceeded')
        body = json.dumps({'method': method, 'params': params, 'id': self.calls}).encode()
        req = urllib.request.Request(self.url, body, {'Content-Type': 'application/json'})
        with self.opener.open(req, timeout=min(15, remaining)) as response:
            raw = response.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, 'oversized_rpc')
        result = json.loads(raw, object_pairs_hook=unique)
        require(isinstance(result, dict) and result.get('id') == self.calls
                and result.get('error') is None and 'result' in result, 'rpc_failed')
        return result['result']

    def __call__(self, method, *args):
        return self.request(method, [self.key, *args])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--initialize', action='store_true')
    args = parser.parse_args(argv)
    api = None
    try:
        config = read_json(Path(args.config))
        require(isinstance(config, dict) and set(config) == {'endpoint', 'username', 'password', 'surveys', 'state'}, 'invalid_config')
        surveys(config)
        require(all(isinstance(config[x], str) and config[x] for x in ('endpoint', 'username', 'password', 'state')), 'invalid_config')
        path = Path(config['state'])
        require(path.is_absolute() and path.parent.is_dir()
                and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
                and path.parent.stat().st_uid == os.getuid(), 'unsafe_directory')
        lockpath = path.parent / (path.name + '.lock')
        fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            private(lockpath)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            api = RPC(config)
            result = run(config, path, api, int(time.time()), initialize=args.initialize, apply=args.apply)
            print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        # Neither upstream errors nor paths/credentials/IDs enter journal output.
        print('retention_failed: inspect private configuration and monitoring', file=sys.stderr)
        return 1
    finally:
        if api is not None:
            try:
                api('release_session_key')
            except Exception:
                pass


if __name__ == '__main__':
    sys.exit(main())
