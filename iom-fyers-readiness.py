#!/usr/bin/env python3
"""One-shot FYERS account inspection. Fixed GET allowlist; no trading methods.

Run with sudo on the existing AWS host. Reads the mentor service's App ID and
stored token; never writes files, refreshes credentials, starts services or logs
broker payloads. Profile identity is verified before reading funds/exposure.
"""
import base64
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

HOST = 'https://api-t1.fyers.in/api/v3'
READ_ROUTES = frozenset({'profile', 'funds', 'orders', 'positions'})
SERVICES = ('index-options-mentor.service', 'index-options-journal.service',
            'index-options-execution-check.service', 'index-options-journal-daily.timer')
BASE = Path('/var/lib/index-options-mentor')


class CheckFailed(Exception):
    """Only constant reasons and bounded numeric FYERS codes may leave this module."""
    def __init__(self, reason, *, http_status=None, broker_code=None):
        super().__init__(reason)
        self.http_status = http_status
        self.broker_code = broker_code


def broker_failure(data, http_status=None):
    code = data.get('code') if isinstance(data, dict) else None
    code = code if type(code) is int and -100000 <= code <= 999999 else None
    if code == -8:
        reason = 'FYERS_LOGIN_EXPIRED'
    elif code in (-15, -16, -17):
        reason = 'FYERS_LOGIN_INVALID_OR_UNAUTHENTICATED'
    elif http_status is not None:
        reason = 'FYERS_HTTP_' + str(http_status)
    else:
        reason = 'FYERS_READ_REJECTED'
    return CheckFailed(reason, http_status=http_status, broker_code=code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class ReadOnlyClient:
    def __init__(self, app_id, token, opener=None):
        if not isinstance(app_id, str) or not re.fullmatch(r'[A-Za-z0-9]{4,40}-[0-9]{3}', app_id):
            raise CheckFailed('APP_ID_FORMAT_UNRECOGNISED')
        if not isinstance(token, str) or any(c in token for c in ('\r', '\n')):
            raise CheckFailed('STORED_TOKEN_FORMAT_UNRECOGNISED')
        if ':' in token:
            prefix, token = token.split(':', 1)
            if prefix != app_id:
                raise CheckFailed('STORED_TOKEN_APP_MISMATCH')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{20,16384}', token):
            raise CheckFailed('STORED_TOKEN_FORMAT_UNRECOGNISED')
        self._authorization = app_id + ':' + token
        # No environment proxy and no redirects: credentials stay on FYERS HTTPS.
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, route):
        if route not in READ_ROUTES:
            raise CheckFailed('READ_ONLY_ROUTE_REQUIRED')
        request = urllib.request.Request(HOST + '/' + route, method='GET', headers={
            'Authorization': self._authorization, 'Accept': 'application/json',
            'User-Agent': 'IOM-read-only-readiness/1'})
        try:
            with self._opener.open(request, timeout=8) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise CheckFailed('FYERS_RESPONSE_TOO_LARGE')
                data = json.loads(raw)
        except urllib.error.HTTPError as error:
            status = error.code
            try:
                raw = error.read(65537)
                data = json.loads(raw) if len(raw) <= 65536 else None
            except (OSError, ValueError):
                data = None
            finally:
                error.close()
            # FYERS auth errors can arrive with HTTP 400. Never discard their
            # numeric code; never forward the potentially private message/body.
            raise broker_failure(data, status) from None
        except (OSError, ValueError, urllib.error.URLError):
            raise CheckFailed('FYERS_READ_UNAVAILABLE') from None
        if not isinstance(data, dict) or data.get('s') != 'ok':
            raise broker_failure(data)
        return data

    def place_order(self, *args, **kwargs):
        raise CheckFailed('REAL_ORDERS_DISABLED')

    cancel_order = place_order
    modify_order = place_order
    exit_positions = place_order


def secure_json(path, mentor_uid):
    path = Path(path)
    try:
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise CheckFailed('UNSAFE_CONFIGURATION_PATH')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, mentor_uid)
                    or info.st_mode & 0o027 or info.st_size > 1_000_000):
                raise CheckFailed('UNSAFE_CONFIGURATION_PERMISSIONS')
            raw = handle.read(1_000_001)
        if len(raw) > 1_000_000:
            raise CheckFailed('CONFIGURATION_TOO_LARGE')
        return json.loads(raw)
    except (OSError, ValueError):
        raise CheckFailed('CONFIGURATION_UNAVAILABLE_OR_INVALID') from None


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)


def extract_token(stored):
    candidates = set()
    def visit(value, depth=0):
        if depth > 3 or not isinstance(value, dict):
            return
        for key, child in value.items():
            if key in ('access_token', 'accessToken', 'token') and isinstance(child, str) and child:
                candidates.add(child)
            elif isinstance(child, dict):
                visit(child, depth + 1)
    if isinstance(stored, str) and stored:
        candidates.add(stored)
    else:
        visit(stored)
    if len(candidates) != 1:
        raise CheckFailed('STORED_TOKEN_MISSING_OR_AMBIGUOUS')
    return candidates.pop()


def owner_proof(pin):
    proofs = {v for v in strings(pin) if re.fullmatch('[a-f0-9]{64}', v)}
    if len(proofs) != 1:
        raise CheckFailed('PINNED_OWNER_MISSING_OR_AMBIGUOUS')
    return proofs.pop()


def verify_owner(profile, secret, expected):
    data = profile.get('data')
    identity = data.get('fy_id') if isinstance(data, dict) else None
    if not isinstance(identity, str) or not identity:
        raise CheckFailed('FYERS_PROFILE_INVALID')
    actual = hmac.new(secret.encode(), ('FYERS_OWNER_V1:' + identity).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise CheckFailed('FYERS_ACCOUNT_DOES_NOT_MATCH_PINNED_OWNER')


def inspect_broker(client, secret, expected):
    # Wrong-account calls stop after profile; never inspect another account.
    verify_owner(client.get('profile'), secret, expected)
    result = {'accountMatchesAws': True, 'brokerReads': {}}
    for route, field in (('funds', 'fund_limit'), ('orders', 'orderBook'), ('positions', 'netPositions')):
        try:
            rows = client.get(route).get(field)
            if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
                raise CheckFailed('FYERS_' + route.upper() + '_INVALID')
            if route == 'funds':
                matches = [r for r in rows if r.get('id') == 10]
                amount = matches[0].get('equityAmount') if len(matches) == 1 else None
                if (type(amount) not in (int, float) or not math.isfinite(amount) or amount < 0):
                    raise CheckFailed('FYERS_FUNDS_INVALID')
                # Report access only, never the account balance.
                result['brokerReads'][route] = {'passed': True}
            elif route == 'positions':
                if any(type(r.get('netQty')) is not int for r in rows):
                    raise CheckFailed('FYERS_POSITIONS_INVALID')
                result['brokerReads'][route] = {
                    'passed': True, 'openPositionCount': sum(r['netQty'] != 0 for r in rows)}
            else:
                result['brokerReads'][route] = {'passed': True, 'orderCount': len(rows)}
        except CheckFailed as error:
            result['brokerReads'][route] = {'passed': False, 'reason': str(error),
                'httpStatus': error.http_status, 'brokerCode': error.broker_code}
    result['readOnlyBrokerAccessPassed'] = all(r['passed'] for r in result['brokerReads'].values())
    return result


def service_state():
    states = {}
    for service in SERVICES:
        try:
            result = subprocess.run(['systemctl', 'show', service,
                '--property=ActiveState,MainPID'], capture_output=True, text=True, check=True, timeout=5)
            properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            states[service] = {'active': properties.get('ActiveState') == 'active',
                               'pid': int(properties.get('MainPID', '0'))}
        except (subprocess.SubprocessError, OSError, ValueError):
            raise CheckFailed('SERVICE_STATE_UNAVAILABLE') from None
    return states


def service_app_id(pid, mentor_uid):
    if type(pid) is not int or pid <= 0:
        raise CheckFailed('MENTOR_SERVICE_NOT_RUNNING')
    try:
        status = Path('/proc', str(pid), 'status').read_text()
        match = re.search(r'^Uid:\s+(\d+)', status, re.M)
        if not match or int(match[1]) != mentor_uid:
            raise CheckFailed('MENTOR_SERVICE_USER_MISMATCH')
        raw = Path('/proc', str(pid), 'environ').read_bytes()
        entries = [row.split(b'=', 1)[1].decode('utf8') for row in raw.split(b'\0')
                   if row.startswith(b'FYERS_APP_ID=')]
        if len(entries) != 1:
            raise CheckFailed('SERVICE_APP_ID_UNAVAILABLE')
        return entries[0]
    except (OSError, UnicodeError):
        raise CheckFailed('SERVICE_CONFIGURATION_UNAVAILABLE') from None



def local_login_hints(token, app=Path('/opt/index-options-mentor/app')):
    """Non-secret hints only. JWT expiry is a hint, never trusted authentication."""
    hints = {}
    try:
        value = token.split(':', 1)[-1]
        parts = value.split('.')
        if len(parts) == 3 and len(parts[1]) < 20000:
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
            expiry = payload.get('exp') if isinstance(payload, dict) else None
            if type(expiry) in (int, float) and math.isfinite(expiry):
                hints['storedTokenExpiryTimePassed'] = expiry <= time.time()
    except (ValueError, UnicodeError):
        pass
    try:
        source = (app/'fyersAuthRoutes.mjs').read_text()[:100000]
        literals = re.findall(r"[\"'](/[A-Za-z0-9_./-]{1,120})[\"']", source)
        paths = sorted({path for path in literals if 'fyers' in path.lower()
                        and path.rstrip('/').rsplit('/', 1)[-1].lower() in ('login', 'connect', 'auth')
                        and not any(word in path.lower() for word in ('callback', '..'))})
        if len(paths) == 1:
            hints['internalAwsLoginRoute'] = paths[0]
            hints['publicAwsLoginUrlVerified'] = False
    except OSError:
        pass
    return hints


def main():
    report = {'stage': 'READ_ONLY_ACCOUNT_CHECK', 'realMoneyEnabled': False,
              'ordersSent': 0, 'filesModified': False, 'servicesRestarted': False,
              'tradingPermissionsVerified': False, 'webSocketExitVerified': False,
              'brokerStopsVerified': False}
    before = None
    try:
        if os.geteuid() != 0:
            raise CheckFailed('RUN_WITH_SUDO_ON_AWS')
        mentor_uid = pwd.getpwnam('mentor').pw_uid
        before = service_state()
        if not all(row['active'] for row in before.values()):
            raise CheckFailed('EXISTING_SERVICE_NOT_ACTIVE')
        app_id = service_app_id(before[SERVICES[0]]['pid'], mentor_uid)
        stored = secure_json(BASE / 'fyers-token.json', mentor_uid)
        token = extract_token(stored)
        report.update(local_login_hints(token))
        config = secure_json('/etc/index-options-journal.json', mentor_uid)
        secret = config.get('secret') if isinstance(config, dict) else None
        if not isinstance(secret, str) or len(secret) < 32:
            raise CheckFailed('BRIDGE_SECRET_UNAVAILABLE')
        expected = owner_proof(secure_json(BASE / 'paper-owner.json', mentor_uid))
        report.update(inspect_broker(ReadOnlyClient(app_id, token), secret, expected))
    except CheckFailed as error:
        report['blocker'] = str(error)
        report['httpStatus'] = error.http_status
        report['brokerCode'] = error.broker_code
    except Exception:
        # Never print exceptions, object reprs, token values or broker responses.
        report['blocker'] = 'LOCAL_READINESS_CHECK_FAILED'
    finally:
        if before is not None:
            try:
                report['existingServicesUnchanged'] = before == service_state()
            except CheckFailed:
                report['existingServicesUnchanged'] = False
            if not report['existingServicesUnchanged']:
                report['blocker'] = 'EXISTING_SERVICE_STATE_CHANGED_DURING_CHECK'
        report['checkedAtUnix'] = int(time.time())
        print(json.dumps(report, sort_keys=True))
    return 0 if report.get('readOnlyBrokerAccessPassed') and not report.get('blocker') else 1


if __name__ == '__main__':
    sys.exit(main())
