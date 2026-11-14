"""Core logic for input_conf_generator_ds.

Kept free of any ``splunk`` imports so it can be unit tested outside Splunk.

Everything that ends up in a .conf file goes through ``validate_payload`` first.
Values are written verbatim into inputs.conf / serverclass.conf, so the
validation rules below are what stop a request from injecting extra stanzas
(newlines), line continuations (trailing backslash) or escaping the
deployment-apps directory (path separators / "..").
"""

import contextlib
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

try:  # POSIX deployment servers
    import fcntl
except ImportError:  # pragma: no cover - Windows deployment servers
    fcntl = None


# ---------------------------------------------------------------------------
# Naming conventions. Customise here if your naming standard differs.
# ---------------------------------------------------------------------------
PRECEDENCE_PREFIX = {"low": "z_", "normal": "y_", "high": "_"}
PRECEDENCE_ALIASES = {"higher": "high"}  # older SH builds sent "higher"


def build_app_name(precedence, environment, index, app_name):
    return f"{PRECEDENCE_PREFIX[precedence]}{environment}_{index}_{app_name}"


def build_serverclass_name(deployment_app, index, sourcetype):
    # Unchanged from the original naming so existing server classes keep matching.
    return f"{deployment_app}_{index}_{sourcetype}"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
MAX_ITEMS = 100
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,79}$")
SOURCETYPE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,99}$")
VERSION_RE = re.compile(r"^\d{1,4}(\.\d{1,4}){0,3}$")
HOST_RE = re.compile(r"^[A-Za-z0-9*][A-Za-z0-9_.*:-]{0,252}$")
WILDCARD_ONLY_RE = re.compile(r"^[*._:-]+$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
ABSOLUTE_PATH_RE = re.compile(r"^(/|[A-Za-z]:[\\/]|\\\\)")


class ValidationError(ValueError):
    def __init__(self, errors):
        super().__init__("; ".join(errors))
        self.errors = errors


def _as_list(value):
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return None
    out = []
    for item in value:
        if not isinstance(item, str):
            return None
        item = item.strip()
        if item and item not in out:
            out.append(item)
    return out


def _check_source(path):
    if len(path) > 1024:
        return "is longer than 1024 characters"
    if CONTROL_CHARS_RE.search(path):
        return "contains control characters (e.g. newlines)"
    if path.endswith("\\"):
        return "must not end with a backslash (it would continue the .conf line)"
    if not ABSOLUTE_PATH_RE.match(path):
        return "must be an absolute path"
    return None


def _check_host(host):
    if not HOST_RE.match(host):
        return "may only contain letters, digits, '.', '-', '_', ':' and '*'"
    if WILDCARD_ONLY_RE.match(host):
        return "must not be a wildcard-only pattern (it would match every client)"
    return None


def clean_message(message):
    """Single-line, bounded message suitable for a .conf comment."""
    return CONTROL_CHARS_RE.sub(" ", message).strip()[:256]


def validate_payload(payload):
    """Return a normalised dict or raise ValidationError listing every problem."""
    if not isinstance(payload, dict):
        raise ValidationError(["payload must be a JSON object"])

    errors = []
    meta = payload.get("additional_metadata") or {}
    if not isinstance(meta, dict):
        errors.append("additional_metadata must be an object")
        meta = {}

    def text(container, key, default=""):
        value = container.get(key, default)
        if value is None:
            value = default
        if not isinstance(value, str):
            errors.append(f"{key} must be a string")
            return ""
        return value.strip()

    message = clean_message(text(payload, "message"))
    if not message:
        errors.append("message is required")

    precedence = text(payload, "precedence", "low").lower()
    precedence = PRECEDENCE_ALIASES.get(precedence, precedence)
    if precedence not in PRECEDENCE_PREFIX:
        errors.append(f"precedence must be one of {sorted(PRECEDENCE_PREFIX)}")

    index = text(payload, "my_index")
    if not INDEX_RE.match(index):
        errors.append("my_index must be lowercase letters, digits, '_' or '-' and not start with '_' or '-'")

    sourcetype = text(payload, "my_sourcetype")
    if not SOURCETYPE_RE.match(sourcetype):
        errors.append("my_sourcetype may only contain letters, digits, '_', '.', ':' and '-'")

    app_name = text(meta, "app_name")
    if not NAME_RE.match(app_name):
        errors.append("app_name may only contain letters, digits, '_' and '-' (max 80)")

    environment = text(meta, "environment")
    if not NAME_RE.match(environment):
        errors.append("environment may only contain letters, digits, '_' and '-' (max 80)")

    version = text(meta, "version", "1.0.0") or "1.0.0"
    if not VERSION_RE.match(version):
        errors.append("version must look like 1.0.0")

    requested_by = clean_message(text(meta, "requested_by"))[:128]

    sources = _as_list(payload.get("my_source", []))
    if sources is None:
        errors.append("my_source must be a list of strings")
        sources = []
    elif not sources:
        errors.append("at least one source path is required")
    elif len(sources) > MAX_ITEMS:
        errors.append(f"at most {MAX_ITEMS} source paths per request")
    for path in sources:
        problem = _check_source(path)
        if problem:
            errors.append(f"source {path!r} {problem}")

    hosts = _as_list(payload.get("my_host", []))
    if hosts is None:
        errors.append("my_host must be a list of strings")
        hosts = []
    elif not hosts:
        errors.append("at least one host is required")
    elif len(hosts) > MAX_ITEMS:
        errors.append(f"at most {MAX_ITEMS} hosts per request")
    for host in hosts:
        problem = _check_host(host)
        if problem:
            errors.append(f"host {host!r} {problem}")

    if errors:
        raise ValidationError(errors)

    deployment_app = build_app_name(precedence, environment, index, app_name)
    return {
        "message": message,
        "precedence": precedence,
        "index": index,
        "sourcetype": sourcetype,
        "sources": sources,
        "hosts": hosts,
        "app_name": app_name,
        "environment": environment,
        "version": version,
        "requested_by": requested_by,
        "deployment_app": deployment_app,
        "serverclass": build_serverclass_name(deployment_app, index, sourcetype),
    }


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------
_thread_lock = threading.Lock()


@contextlib.contextmanager
def config_lock(lock_path):
    """Serialise writers across threads and (on POSIX) across processes."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock:
        with open(lock_path, "a") as handle:
            if fcntl:
                fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl:
                    fcntl.flock(handle, fcntl.LOCK_UN)


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", newline="\n") as handle:
            handle.write(content)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read(path):
    path = Path(path)
    return path.read_text() if path.exists() else ""


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def contained_path(base, *parts):
    """Join and make sure the result stays inside ``base`` (defence in depth)."""
    base = Path(base).resolve()
    target = base.joinpath(*parts).resolve()
    if target != base and base not in target.parents:
        raise ValidationError([f"resolved path {target} escapes {base}"])
    return target


STANZA_RE = re.compile(r"^\s*\[(?P<name>.*)\]\s*$")


def existing_stanzas(conf_text):
    names = set()
    for line in conf_text.splitlines():
        match = STANZA_RE.match(line)
        if match:
            names.add(match.group("name"))
    return names


# ---------------------------------------------------------------------------
# Deployment app (app.conf + inputs.conf)
# ---------------------------------------------------------------------------
def render_app_conf(app, version, created):
    return (
        "# This app is generated by input_conf_generator_ds. Do not edit by hand:\n"
        "# changes may be overwritten by the next automated update.\n"
        f"# Created: {created}\n"
        f"# Updated: {_now()}\n"
        "\n"
        "[install]\n"
        "state = enabled\n"
        "\n"
        "[package]\n"
        f"id = {app}\n"
        "check_for_updates = false\n"
        "\n"
        "[id]\n"
        f"name = {app}\n"
        f"version = {version}\n"
        "\n"
        "[launcher]\n"
        f"version = {version}\n"
        "author = input_conf_generator\n"
        "description = Inputs generated by input_conf_generator_ds\n"
        "\n"
        "[ui]\n"
        "is_visible = false\n"
        f"label = {app}\n"
    )


def update_deployment_app(deployment_apps_dir, data, dry_run=False):
    """Create/refresh app.conf and append new monitor stanzas to inputs.conf."""
    app = data["deployment_app"]
    default_dir = contained_path(deployment_apps_dir, app, "default")
    app_conf = default_dir / "app.conf"
    inputs_conf = default_dir / "inputs.conf"

    is_new_app = not app_conf.exists()
    created = _now()
    if not is_new_app:
        match = re.search(r"^# Created: (.+)$", _read(app_conf), re.M)
        if match:
            created = match.group(1).strip()
    if not dry_run:
        atomic_write(app_conf, render_app_conf(app, data["version"], created))

    current = _read(inputs_conf)
    present = existing_stanzas(current)
    added, skipped = [], []
    for source in data["sources"]:
        stanza = f"monitor://{source}"
        (skipped if stanza in present else added).append(source)
        present.add(stanza)

    if added and not dry_run:
        block = [
            "",
            f"# *** Start of inputs from: {data['message']}",
            f"# *** Requested by: {data['requested_by'] or 'unknown'} at {_now()}",
        ]
        for source in added:
            block += [
                f"[monitor://{source}]",
                f"index = {data['index']}",
                f"sourcetype = {data['sourcetype']}",
                "disabled = false",
                "",
            ]
        block += [f"# *** End of inputs from: {data['message']}", ""]
        if current and not current.endswith("\n"):
            current += "\n"
        atomic_write(inputs_conf, current + "\n".join(block))

    return {"app": app, "new_app": is_new_app, "inputs_added": added, "inputs_skipped": skipped}


# ---------------------------------------------------------------------------
# serverclass.conf
# ---------------------------------------------------------------------------
HELPER_APP_CONF = (
    "# Holds server classes generated by input_conf_generator_ds.\n"
    "[install]\nstate = enabled\n\n"
    "[package]\nid = input_conf_generator_serverclass\ncheck_for_updates = false\n\n"
    "[ui]\nis_visible = false\nlabel = Input conf generator - server classes\n"
)


def _stanza_span(conf_text, stanza):
    """(start, end) character offsets of a stanza's body, or None."""
    header = re.compile(rf"^\s*\[{re.escape(stanza)}\]\s*$", re.M)
    match = header.search(conf_text)
    if not match:
        return None
    following = re.compile(r"^\s*\[", re.M).search(conf_text, match.end())
    return match.end(), following.start() if following else len(conf_text)


def update_serverclass(serverclass_app_dir, data, dry_run=False):
    app_dir = Path(serverclass_app_dir)
    if not dry_run and not (app_dir / "default" / "app.conf").exists():
        atomic_write(app_dir / "default" / "app.conf", HELPER_APP_CONF)
    path = app_dir / "local" / "serverclass.conf"

    name, app = data["serverclass"], data["deployment_app"]
    text = _read(path)
    if text and not text.endswith("\n"):
        text += "\n"

    existing_hosts, max_index = set(), -1
    span = _stanza_span(text, f"serverClass:{name}")
    if span:
        for num, host in re.findall(r"^\s*whitelist\.(\d+)\s*=\s*(\S+)\s*$", text[span[0]:span[1]], re.M):
            existing_hosts.add(host)
            max_index = max(max_index, int(num))

    new_hosts = [h for h in data["hosts"] if h not in existing_hosts]
    skipped = [h for h in data["hosts"] if h in existing_hosts]

    changed = False
    if span is None:
        lines = [f"# Added on {_now()} by {data['requested_by'] or 'unknown'}", f"[serverClass:{name}]"]
        lines += [f"whitelist.{i} = {h}" for i, h in enumerate(new_hosts)]
        text += "\n" + "\n".join(lines) + "\n"
        changed, status = True, "created"
    elif new_hosts:
        lines = [f"# Updated on {_now()} by {data['requested_by'] or 'unknown'}"]
        lines += [f"whitelist.{i} = {h}" for i, h in enumerate(new_hosts, start=max_index + 1)]
        body = text[span[0]:span[1]].rstrip("\n") + "\n" + "\n".join(lines) + "\n\n"
        text = text[:span[0]] + body + text[span[1]:].lstrip("\n")
        changed, status = True, "updated"
    else:
        status = "unchanged"

    app_stanza = f"serverClass:{name}:app:{app}"
    if _stanza_span(text, app_stanza) is None:
        text += (
            f"\n[{app_stanza}]\n"
            "restartSplunkWeb = 0\n"
            "restartSplunkd = 1\n"
            "stateOnClient = enabled\n"
        )
        changed = True

    if changed and not dry_run:
        atomic_write(path, text)
    return {"serverclass": name, "serverclass_status": status, "hosts_added": new_hosts, "hosts_skipped": skipped}


def apply_payload(splunk_home, data, dry_run=False):
    """Apply a validated payload. Inputs and server class are handled independently,
    so re-submitting existing sources with new hosts still adds the hosts.
    With ``dry_run`` nothing is written; the result reports what would change."""
    splunk_home = Path(splunk_home)
    lock = splunk_home / "var" / "run" / "splunk" / "input_conf_generator_ds.lock"
    with config_lock(lock):
        result = update_deployment_app(splunk_home / "etc" / "deployment-apps", data, dry_run)
        result.update(update_serverclass(splunk_home / "etc" / "apps" / "input_conf_generator_serverclass", data, dry_run))
    result["dry_run"] = dry_run
    return result
