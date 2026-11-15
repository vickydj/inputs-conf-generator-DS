# Rest handler to generate confs

## Overview

    This app sits on deployment servers, receives payload from the SH app <app-name here>.
  
    The python program decodes the payload and generates inputs.conf and serverclass.conf
  
    Checks for existing app/conf files and adds only new updates. Duplicates are ignored.

## Security

- `/services/receive_payload` requires a login with the `input_conf_generator_write` capability (`default/authorize.conf`).
- Give the account whose token the SH app uses only the `input_conf_generator_sender` role.
- Every field is validated before it is written to `inputs.conf` or `serverclass.conf`.
  Bad input gets a `400` that lists the problems.
- `submitted_by` (set by the SH from the Splunk session) is written in the comments of `inputs.conf` and `serverclass.conf`.
- The request body is plain JSON (see the SH app). Supports Splunk Enterprise 10.x and 9.x, Python 3 only (see the SH app).

Every pull request runs `.github/workflows/validate.yml`. It fails if:
- a test fails;
- `local/`, `local.meta`, `*.backup`, a token, a `$7$` secret or a private key is committed;
- a REST endpoint skips authentication, `web.conf` exposes an endpoint, or Python turns off TLS verification;
- Splunk AppInspect (precert) reports any failure.

Make **Validate Splunk app** a required status check on `master`. Locally, `python3 -m unittest discover -s tests` runs the tests.

## Upgrading from 1.0.x

Upgrade this DS app **before** the SH app. The DS accepts payloads from SH 1.0.x and 1.1+; DS 1.0.x cannot read SH 1.1+.

- Server class names no longer contain `:`. It is replaced by `_`: sourcetype `nginx:access` gives `..._nginx_access`.
  Classes made by older releases keep their old names. Resubmitting creates the new class with all its hosts.
  Then delete the old class from `etc/apps/input_conf_generator_serverclass/local/serverclass.conf`.
- Generated deployment apps now get real `[launcher] version` and `[package] id` stanzas in `app.conf`.
  Comment-only `app.conf` files from older releases are rewritten on the next request for that app.
  The version only moves forward. Timestamps in generated comments are UTC.

## Server class reload

Each server class that a payload creates or changes is queued in `$SPLUNK_HOME/var/run/input_conf_generator_ds/pending_reload`.
The scripted input `bin/reload_pending_serverclasses.py` (every 300 s, `default/inputs.conf`) reloads only those classes and
keeps any that fail for the next run. Change `interval` in `local/inputs.conf` to reload more or less often.

## Phoning-home clients

The SH reads the client list from the DS's own `/services/deployment/server/clients` endpoint with its token
(the `input_conf_generator_sender` role has `list_deployment_server`), so this app needs no extra handler.

## To do
- Delete a source/app, probably in a new endpoint.
- Update a source/app, probably in a new endpoint.
