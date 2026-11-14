# input_conf_generator_ds

Deployment-server half of the Input Conf Generator. It works together with
[`input_conf_generator_sh`](https://github.com/vickydj/inputs-conf-generator-SH),
which collects requests on a search head and sends them here.

## Requirements

* Splunk Enterprise **10.2+** with **Python 3.13 or 3.14**. Scripts declare
  `python.required = 3.13, 3.14`. Python 2 and older Python 3 runtimes aren't supported.
* Standard library only, no third-party dependencies.

## What it does

`POST /services/receive_payload` (management port, JSON body). For each request it:

1. Validates every field. Anything that could inject extra `.conf` lines (newlines,
   control characters, a trailing `\`), escape `etc/deployment-apps` (`/`, `..` in
   names), or whitelist every client (`*`) gets a `400` response that lists the problems.
2. Creates or refreshes `etc/deployment-apps/<prefix><env>_<index>_<app>/default/app.conf`
   and appends any new `[monitor://…]` stanzas to `inputs.conf`. Stanzas that already exist are skipped.
3. Adds any new hosts to `[serverClass:<app>_<index>_<sourcetype>]` in
   `etc/apps/input_conf_generator_serverclass/local/serverclass.conf`.
   Steps 2 and 3 run independently, so adding hosts to sources that already exist works.

Writes are serialised with a lock file and replaced atomically.
Send `"dry_run": true` in the body to validate the request and see what would change, without writing anything.
The response contains `inputs_added`, `inputs_skipped`, `hosts_added`, `hosts_skipped` and `serverclass_status`.

| precedence | app prefix |
|------------|-----------|
| `low`      | `z_`      |
| `normal`   | `y_`      |
| `high`     | `_`       |

You can change the naming in `bin/input_conf_generator_lib.py`, in `build_app_name` and `build_serverclass_name`.

## Security model

* `restmap.conf` sets `requireAuthentication = true` and `capability = input_conf_generator_write`.
* `authorize.conf` grants that capability to `admin`. It also defines the role
  `input_conf_generator_sender`, which can submit payloads and reload the deployment server.
* The endpoint isn't exposed through Splunk Web (there is no `web.conf`). Only the management port serves it.

## Install

1. Install the app on the deployment server and restart Splunk.
2. Create a service account that has **only** the `input_conf_generator_sender` role.
3. Create an auth token for that account (Settings → Tokens) with a sensible expiry.
4. Enter the DS host, port and token on the search head app's setup page.

## Development

Use Python 3.13+.

```bash
python3 -m unittest discover -s tests     # no Splunk installation required
```

Leave `tests/` out of the app package. Package with
`tar --exclude=tests --exclude=.git -czf input_conf_generator_ds.tgz input_conf_generator_ds`
and check the package with [Splunk AppInspect](https://dev.splunk.com/enterprise/docs/developapps/testvalidate/appinspect/).

## Changelog

### 1.1.0
* **Breaking:** the endpoint now requires authentication and the `input_conf_generator_write`
  capability. The body is plain JSON (the single-quote/escape encoding has been removed). Upgrade both apps together.
* `dry_run` mode for previews.
* Python 3 only: targets Python 3.13/3.14 (`python.required`) on Splunk 10.2+.
* Strict input validation (prevents stanza injection and path traversal).
* Adding hosts to existing sources now works.
* The `"higher"` precedence sent by older SH builds is accepted as `"high"`.
* Generated deployment apps get a complete `app.conf`.
* Proper HTTP status codes: 400 validation, 405 method, 413 size, 500 write failure.
* Removed the dead `reloadsrvcls` command and the `web.conf` expose.

## To do

* Endpoints to update or delete sources and apps.
* An endpoint to list phoned-home clients so the SH can offer a host picker.
