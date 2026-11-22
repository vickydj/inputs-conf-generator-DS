# Inputs conf generator - DS addon (input_conf_generator_ds)

Self-service log onboarding for Splunk deployment servers.

This add-on runs on the **deployment server (DS)**. It receives onboarding requests from its companion app,
**Inputs conf generator - SH app** (`input_conf_generator_sh`, [Splunkbase 7676](https://splunkbase.splunk.com/app/7676)),
which runs on a search head. For each request it:

1. creates or updates a deployment app in `$SPLUNK_HOME/etc/deployment-apps/` with `[monitor://...]` stanzas in `inputs.conf`;
2. creates or updates a server class that maps the requested hosts to that app, through the deployment server's own REST
   API (`/services/deployment/server/serverclasses` and `/applications`). Splunk stores it in
   `$SPLUNK_HOME/etc/apps/input_conf_generator_ds/local/serverclass.conf`, and it shows in Forwarder Management;
3. reloads only the server classes it changed, so forwarders pick up new or changed inputs.

Existing stanzas and hosts are never duplicated or removed.

Both apps are needed. Install the same version of both (see [Upgrading](#upgrading-from-10x)).

## Version support

| Component | Supported |
|---|---|
| Splunk Enterprise | 9.3 – 10.6 (role: deployment server) |
| Python | 3 only (`python.required = 3.9, 3.13, 3.14`) |
| Splunk Cloud Platform | Not applicable: a deployment server is always on-premises |
| Companion app | Inputs conf generator - SH app, same version |

## System requirements

- A Splunk Enterprise instance that acts as the deployment server, with a license that includes the
  deployment server (the Splunk Free license does not).
- The search head that runs the SH app must reach the DS management port (default 8089) over HTTPS.
- Token authentication enabled on the DS (**Settings > Tokens > Token settings**).

## External data sources

None. The add-on makes no outbound connections. It only answers requests on the DS's own management port.

## Installation

Install on the **deployment server only**. Do not install it on forwarders, indexers or search heads.

1. **Apps > Manage Apps > Install app from file** and upload the package, or extract it to `$SPLUNK_HOME/etc/apps/`.
2. Restart Splunk.

## Configuration

1. Create a dedicated user on the DS (**Settings > Users > New user**) with only the role
   **input_conf_generator_sender**. The role is defined by this add-on (`default/authorize.conf`) and has:
   - `input_conf_generator_write`: call `/services/receive_payload`;
   - `list_deployment_server`: lets the SH app list the deployment clients.
2. Create an authentication token for that user (**Settings > Tokens > New token**).
3. Enter the DS host, management port and this token on the SH app's setup page.

Optional, in `local/inputs.conf`: the server class reload runs every 300 seconds. Change `interval` on the stanza
`[script://$SPLUNK_HOME/etc/apps/input_conf_generator_ds/bin/reload_pending_serverclasses.py]` to reload more or less often.

## What gets written

| Request field | Result |
|---|---|
| precedence `low` / `normal` / `high` | App name prefix `z_` / `y_` / `_` (alphabetical order decides config precedence) |
| environment, index, app name | Deployment app `<prefix><environment>_<index>_<app name>` |
| sources | One `[monitor://<source>]` stanza each, with `index`, `sourcetype` and `disabled = false` |
| hosts | `whitelist.N` entries of server class `<app>_<index>_<sourcetype>` (wildcards such as `web*` allowed; characters other than letters, digits, `_ . -` in the name become `_`) |
| message, submitted_by | Comments in `inputs.conf` and lines in `input_conf_generator_ds.log`, so every change can be traced to a request and a user |

The indexes must already exist on the indexers.

## Security

- `/services/receive_payload` requires a login with the `input_conf_generator_write` capability.
- Every field is validated before anything is written: single-line values, names limited to letters, digits, `_` and `-`,
  absolute source paths, and no host patterns that match every client. A request that fails validation gets HTTP 400 with
  the list of problems.
- `submitted_by` is set by the SH app from the Splunk session of the user who pressed Submit. A browser cannot change it.

## Troubleshooting

| Symptom | Check |
|---|---|
| The SH reports HTTP 401 | The token is wrong, expired or token authentication is disabled on the DS |
| The SH reports HTTP 403 | The token's user lacks the `input_conf_generator_sender` role |
| HTTP 400 with a list of errors | A field is invalid; the message names the field |
| Forwarders do not get the app | Wait for the reload (300 s) and the client's next phone home; see `index=_internal source=*splunkd.log* DeploymentServer` |

Logs:
- `$SPLUNK_HOME/var/log/splunk/input_conf_generator_ds.log` records every request and what was written:
  `index=_internal source=*input_conf_generator_ds.log`.
- The reload results are indexed with `sourcetype=input_conf_generator`.

## Upgrading from 1.0.x

1.1.0 changes the protocol and requires authentication, so the DS add-on and the SH app must both be upgraded to 1.1.0.
After upgrading, create the user and token above and re-run the SH app's setup page.

1.0.x wrote server classes to `$SPLUNK_HOME/etc/apps/input_conf_generator_serverclass/local/serverclass.conf`, which the
deployment server did not load. To keep those requests, submit them again from the SH app (existing sources and hosts
are not duplicated), then delete the `input_conf_generator_serverclass` folder.

## Support

Developer supported. Open an issue at <https://github.com/vickydj/inputs-conf-generator-DS/issues>.

## Development

| What | Where | When |
|---|---|---|
| Lint: committed `local/`, `local.meta`, `*.backup`, bytecode, tokens, `$7$` secrets or private keys; REST endpoints without authentication; Python that turns off TLS verification | `ci/lint.sh` | pre-push hook, CI |
| Tests | `tests/` (`python3 -m unittest discover -s tests`) | pre-push hook, CI |
| Package for Splunkbase (from the files git tracks; no tests, CI files or dotfiles) | `ci/build.sh` → `dist/` | CI |
| Splunk AppInspect (Splunkbase + Cloud checks) and the Packaging Toolkit (`slim validate`) | `ci/check.sh` | CI |

- **Pull requests and pushes to `master`** run `.github/workflows/validate.yml`. It uploads the package and the
  AppInspect report as a build artifact. Make **Validate Splunk app** a required status check on `master`.
- **Releases**: bump the version in `default/app.conf` (`[launcher]` and `[id]`), add a
  `### <version>` section to the release notes below, merge, then `git tag v<version> && git push origin v<version>`.
  `.github/workflows/release.yml` checks the tag matches the app version, builds and checks the package, and
  publishes a GitHub release with the package, `SHA256SUMS` and the AppInspect report. Upload that package to
  Splunkbase.
- **Pre-push hook**: enable once per clone with `git config core.hooksPath ci/hooks`. It runs the lint and the
  tests (about a second). `git push --no-verify` skips it.

## Release notes

### 1.1.0
- `/services/receive_payload` requires authentication and the `input_conf_generator_write` capability. It no longer
  accepts anonymous requests, and it is no longer exposed through Splunk Web.
- New role `input_conf_generator_sender` for the SH app's token.
- All fields are validated; invalid requests get HTTP 400 with the list of problems.
- Fix: server classes are created through the deployment server REST API. 1.0.x wrote them to
  `etc/apps/input_conf_generator_serverclass`, which the deployment server did not load, so forwarders never received the apps.
- Records the submitting user in `inputs.conf` and in the add-on's log.
- Reloads only the server classes that changed, including when only new sources were added (scripted input, every 300 s).
- The request body is plain JSON.
- Updates the version comment in the deployment app's `app.conf` when a request is sent again with a new version.
- Python 3 only; Splunk Enterprise 9.3 – 10.6.

### 1.0.1
- First Splunkbase release.
