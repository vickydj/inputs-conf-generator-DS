"""Persistent REST handler for /services/receive_payload.

The endpoint requires an authenticated caller holding the
``input_conf_generator_write`` capability (see restmap.conf / authorize.conf).

Request body (JSON):
    {
      "message": "RFC123 - apache logs",
      "precedence": "low" | "normal" | "high",
      "my_index": "web",
      "my_sourcetype": "access_combined",
      "my_source": ["/var/log/httpd/access.log"],
      "my_host": ["web01", "web02"],
      "dry_run": false,          # optional: validate and report, write nothing
      "additional_metadata": {"app_name": "apache", "environment": "prod",
                              "version": "1.0.0", "requested_by": "jdoe"}
    }
"""

import json
import logging
import logging.handlers
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunk.persistconn.application import PersistentServerConnectionApplication  # type: ignore  # noqa: E402

import input_conf_generator_lib as lib  # noqa: E402

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "")
MAX_BODY_BYTES = 256 * 1024


def setup_logger(level=logging.INFO):
    logger = logging.getLogger("input_conf_generator_ds")
    if logger.handlers:  # the persistent process may import us more than once
        return logger
    logger.setLevel(level)
    logger.propagate = False
    log_file = os.path.join(SPLUNK_HOME, "var", "log", "splunk", "input_conf_generator_ds.log")
    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=1000000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
    logger.addHandler(handler)
    return logger


logger = setup_logger()


def _response(status, body):
    return {"payload": body, "status": status, "headers": {"Content-Type": "application/json"}}


class ReceivePayloadHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line, command_arg):
        super(ReceivePayloadHandler, self).__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
        except (TypeError, ValueError):
            logger.error("Could not parse request envelope from splunkd")
            return _response(500, {"status": "error", "message": "Malformed request envelope"})

        method = str(request.get("method", "")).upper()
        user = (request.get("session") or {}).get("user", "unknown")
        if method != "POST":
            return _response(405, {"status": "error", "message": "Only POST is supported"})

        body = request.get("payload") or ""
        if len(body) > MAX_BODY_BYTES:
            return _response(413, {"status": "error", "message": "Request body too large"})

        try:
            parsed = json.loads(body)
            dry_run = isinstance(parsed, dict) and parsed.pop("dry_run", False) is True
            data = lib.validate_payload(parsed)
        except ValueError as exc:  # includes json.JSONDecodeError and ValidationError
            errors = getattr(exc, "errors", [f"Invalid JSON: {exc}"])
            logger.warning("Rejected request from user=%s: %s", user, "; ".join(errors))
            return _response(400, {"status": "error", "message": "Validation failed", "errors": errors})

        # Record both the DS token owner and the SH user who filled in the form.
        sh_user = data["requested_by"]
        data["requested_by"] = f"{sh_user} (via {user})" if sh_user else user
        logger.info(
            "Request dry_run=%s user=%s app=%s serverclass=%s sources=%d hosts=%d message=%r",
            dry_run, data["requested_by"], data["deployment_app"], data["serverclass"],
            len(data["sources"]), len(data["hosts"]), data["message"],
        )

        try:
            result = lib.apply_payload(SPLUNK_HOME, data, dry_run)
        except lib.ValidationError as exc:
            return _response(400, {"status": "error", "message": "Validation failed", "errors": exc.errors})
        except Exception:
            logger.exception("Failed to apply payload for app=%s", data["deployment_app"])
            return _response(500, {"status": "error", "message": "Failed to write configuration; see input_conf_generator_ds.log"})

        logger.info("Applied payload: %s", json.dumps(result))
        return _response(200, {"status": "success", "result": result})

    def handleStream(self, handle, in_string):
        raise NotImplementedError("Streaming is not supported")

    def done(self):
        pass
