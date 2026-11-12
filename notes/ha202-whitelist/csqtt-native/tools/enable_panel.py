#!/usr/bin/env python3
"""Enable the sidebar for an installed app using the current SSH app's Supervisor token.

Run locally in a privileged Home Assistant SSH app, never upload any tokens.
"""
import json
import os
from urllib.request import Request, urlopen

name = 'local_csqtt_native'
token = os.environ.get('SUPERVISOR_TOKEN', '')
if not token:
    raise SystemExit('Supervisor token missing')
req = Request('http://supervisor/addons/' + name + '/options',
              data=json.dumps({'ingress_panel': True}).encode(),
              headers={'Authorization': 'Bearer ' + token,
                       'Content-Type': 'application/json'}, method='POST')
with urlopen(req, timeout=15) as result:
    answer = json.load(result)
print('ingress_panel update:', answer.get('result', 'unknown'))
