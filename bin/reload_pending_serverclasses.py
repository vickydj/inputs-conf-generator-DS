"""Scripted input (passAuth): reloads only the server classes the receive_payload endpoint changed.

receive_process_payload.py appends each changed class to var/run/input_conf_generator_ds/pending_reload.
This script takes that list, reloads each class, and puts back the ones that failed for the next run.
"""
import os
import sys
from pathlib import Path

import splunk.rest  # type: ignore  # ships with Splunk

PENDING = Path(os.environ.get('SPLUNK_HOME', '')) / 'var' / 'run' / 'input_conf_generator_ds' / 'pending_reload'
RELOAD = "/services/deployment/server/config/_reload"


def take_pending():
    """Moves the queue aside so payloads arriving meanwhile start a new one."""
    working = PENDING.with_suffix('.processing')
    if PENDING.exists():
        with PENDING.open() as src, working.open('a') as dst:  # keeps leftovers of a crashed run
            dst.write(src.read())
        PENDING.unlink()
    if not working.exists():
        return [], working
    names = sorted({line.strip() for line in working.read_text().splitlines() if line.strip()})
    return names, working


def reload(session_key, serverclass=None):
    postargs = {"serverclass": serverclass} if serverclass else {}
    response, _ = splunk.rest.simpleRequest(RELOAD, sessionKey=session_key, method="POST", postargs=postargs,
                                            getargs={"output_mode": "json"})
    return 200 <= response.status < 300, response.status


def main(session_key):
    names, working = take_pending()
    failed = []
    for name in names:
        try:
            ok, status = reload(session_key, name)
        except Exception as e:
            ok, status = False, e
        print(f'check=ds_reload serverclass="{name}" status={"ok" if ok else "error"} detail="{status}"')
        if not ok:
            failed.append(name)
    if failed:
        PENDING.parent.mkdir(parents=True, exist_ok=True)
        with PENDING.open('a') as f:
            f.write(''.join(f'{name}\n' for name in failed))
    working.unlink(missing_ok=True)
    return failed


if __name__ == "__main__":
    sys.exit(1 if main(sys.stdin.readline().strip()) else 0)
