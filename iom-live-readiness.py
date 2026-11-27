#!/usr/bin/env python3
"""Check the installed live connection without enabling or placing any order."""
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import uuid

sys.dont_write_bytecode = True
MAIN_APP = 'https://optionsmentor.netlify.app'
LOCAL = 'http://127.0.0.1:9078'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def status_request(base, path, secret, owner, opener=None):
    if (base, path) not in {
        (LOCAL, '/monitor/orders/status'),
        (MAIN_APP, '/api/orders/maintenance-status'),
    }:
        raise ValueError('STATUS_ROUTE_ONLY')
    body = b'{}'
    stamp, nonce = str(int(time.time())), uuid.uuid4().hex
    message = '\n'.join(['v1', stamp, nonce, owner, 'POST', path,
                         hashlib.sha256(body).hexdigest()])
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    request = urllib.request.Request(base + path, body, headers={
        'content-type': 'application/json', 'x-iom-time': stamp,
        'x-iom-nonce': nonce, 'x-iom-owner': owner,
        'x-iom-signature': signature,
    })
    opener = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=30) as response:
        result = json.load(response)
    if result.get('mode') != 'OWNED_EXECUTION_HOST' or result.get('ok') is not True:
        raise ValueError('ORDER_HOST_NOT_VERIFIED')
    return result

def safe_status(result):
    return {
        'connected': True,
        'realMoneyEnabled': result.get('realMoneyEnabled') is True,
        'activeOwnedPositions': len(result.get('positions') or []),
        'attentionRequired': bool(result.get('attentionRequired')),
        'brokerStopsVerified': result.get('brokerStopsVerified') is True,
        'automaticExitStrategiesVerified': result.get('webSocketExitStrategiesVerified', []),
        'actualBrokerAcceptanceVerified': result.get('actualBrokerAcceptanceVerified') is True,
        'amountPerTrade': (result.get('settings') or {}).get('tradeAmount'),
        'liveCoreAutoEntry': (result.get('settings') or {}).get('mentorAutoOpen') is True,
        'liveScalpAutoEntry': (result.get('settings') or {}).get('scalpAutoOpen') is True,
    }

def main():
    report = {'stage': 'LIVE_READINESS_READ_ONLY', 'ordersSent': 0,
              'configurationChanged': False, 'servicesRestarted': False}
    step = 'SERVICES'
    try:
        names = ['index-options-order-host.service', 'index-options-marketdata.service',
                 'index-options-journal.service', 'index-options-journal-daily.timer',
                 'index-options-order-backup.timer']
        report['services'] = {name: subprocess.check_output(
            ['systemctl', 'show', name, '--property=ActiveState', '--value'],
            text=True).strip() for name in names}
        directory = Path(subprocess.check_output([
            'systemctl', 'show', names[0], '--property=WorkingDirectory', '--value'],
            text=True).strip()).resolve()
        if not directory.is_relative_to('/opt/index-options-mentor/order-host/releases'):
            raise ValueError('INSTALLED_ORDER_RELEASE_NOT_FOUND')
        sys.path.insert(0, str(directory / 'aws/live'))
        step = 'TRADING_LOGIN'
        from account_connect import secure_json, verify_owner
        from fyers_rest import FyersRest
        from feed import Feed, INDEX
        account = secure_json('/etc/index-options-live-account.json')
        secret = secure_json('/etc/index-options-journal.json')['secret']
        client = FyersRest(account['appId'], account['accessToken'], send_enabled=False)
        verify_owner(client.get_profile(), account['ownerProof'], secret)
        # The transport instance cannot make broker mutation requests.
        client.funds(); client.orderbook(); client.positions()
        report['tradingLoginAndAccountReadsPassed'] = True
        step = 'LOCAL_ORDER_HOST'
        local = status_request(LOCAL, '/monitor/orders/status', secret, account['ownerProof'])
        report['aws'] = safe_status(local)
        step = 'DEPLOYED_APP_CONNECTION'
        remote = status_request(MAIN_APP, '/api/orders/maintenance-status', secret, account['ownerProof'])
        report['mainApp'] = safe_status(remote)
        step = 'SHARED_FEED'
        try:
            quotes = Feed('/var/lib/index-options-mentor/live-feed')._read()
            report['freshNiftyFeed'] = INDEX in quotes
        except (ValueError, OSError):
            report['freshNiftyFeed'] = False
        report['readyForUserControlledLiveTest'] = bool(
            all(value == 'active' for value in report['services'].values())
            and report['freshNiftyFeed'] and not report['aws']['attentionRequired']
            and report['aws']['activeOwnedPositions'] == 0
            and not report['aws']['realMoneyEnabled']
            and not report['mainApp']['realMoneyEnabled'])
        report['ok'] = True
    except Exception as error:
        reason = str(error)
        report.update(ok=False, failedStep=step,
                      reason=reason if re.fullmatch(r'[A-Z_]{3,100}', reason) else 'CHECK_FAILED')
    print(json.dumps(report, sort_keys=True))

if __name__ == '__main__':
    main()
