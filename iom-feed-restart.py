#!/usr/bin/env python3
"""Make the FYERS price feed service try again by itself after it stops.

The feed program exits "successfully" when its FYERS sign-in has expired, so
systemd's Restart=on-failure leaves it stopped, even after a new sign-in.
This adds one small systemd settings file: try again every 60 seconds.

It changes no program, strategy, order setting or sign-in, and it cannot sign in
to FYERS. A manual `systemctl stop` still keeps the service stopped.
Use --undo to remove the settings file.
"""
import argparse,json,os,subprocess,sys,time
from pathlib import Path

SERVICE='index-options-marketdata.service'
UNIT_DIR=Path('/etc/systemd/system')
MARKER='# IOM_FEED_RESTART_V1'
SETTINGS=MARKER+'''
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=60
'''

def drop_in():return UNIT_DIR/(SERVICE+'.d')/'50-iom-restart.conf'
def run(args):return subprocess.check_output(args,text=True,timeout=60).strip()
def prop(name):return run(['systemctl','show',SERVICE,'--property='+name,'--value'])

def check_target():
    if prop('LoadState')!='loaded':raise RuntimeError('The price feed service was not found. Nothing was changed.')
    if 'fyersMarketDaemon.mjs' not in prop('ExecStart'):raise RuntimeError('The price feed service runs something unexpected. Nothing was changed.')
    path=drop_in()
    if any(p.is_symlink() for p in [path,*path.parents]):raise RuntimeError('Unsafe settings path. Nothing was changed.')
    if path.exists() and not path.read_text().startswith(MARKER):raise RuntimeError('A different settings file already exists. Nothing was changed.')

def install(wait=time.sleep):
    check_target();path=drop_in();previous=path.read_text() if path.exists() else None
    try:
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text(SETTINGS);os.chmod(path,0o644)
        run(['systemctl','daemon-reload'])
        if prop('Restart')!='always' or prop('RestartUSec') not in ('1min','60s'):raise RuntimeError('The new restart setting did not take effect.')
        # Does nothing if the feed is already running.
        run(['systemctl','start',SERVICE])
    except BaseException:
        if previous is None:path.unlink(missing_ok=True)
        else:path.write_text(previous)
        run(['systemctl','daemon-reload'])
        raise
    wait(5)
    running=prop('ActiveState')=='active'
    return {'ok':True,'retriesEvery60Seconds':True,'feedRunningNow':running,
        'next':'Feed is running.' if running else 'Feed is not running yet. After the daily server data sign-in it should start within about a minute. Check again then.',
        'signedInToFyers':'NOT_CHECKED','ordersSent':0}

def undo():
    check_target();path=drop_in();existed=path.exists()
    path.unlink(missing_ok=True);run(['systemctl','daemon-reload'])
    return {'ok':True,'removed':existed,'restartSettingNow':prop('Restart'),'ordersSent':0}

def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--undo',action='store_true')
    args=parser.parse_args()
    if os.geteuid()!=0:raise RuntimeError('Use sudo python3 from SSH.')
    print(json.dumps(undo() if args.undo else install(),indent=2))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('STOP: '+(str(error) if isinstance(error,RuntimeError) else 'A system command failed. Check the service before trying again.'),file=sys.stderr);sys.exit(1)
