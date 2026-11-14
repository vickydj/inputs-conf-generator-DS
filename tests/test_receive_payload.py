"""Run with:  python3 -m unittest discover -s tests   (no Splunk needed)."""
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

BIN = Path(__file__).resolve().parents[1] / "bin"
sys.path.insert(0, str(BIN))

# Stub the splunk module so the handler can be imported outside Splunk.
_pc = types.ModuleType("splunk.persistconn.application")
_pc.PersistentServerConnectionApplication = type("PersistentServerConnectionApplication", (), {"__init__": lambda self: None})
for name, mod in {"splunk": types.ModuleType("splunk"), "splunk.persistconn": types.ModuleType("splunk.persistconn"),
                  "splunk.persistconn.application": _pc}.items():
    sys.modules.setdefault(name, mod)

TMP = tempfile.mkdtemp()
os.environ["SPLUNK_HOME"] = TMP
os.makedirs(os.path.join(TMP, "var", "log", "splunk"), exist_ok=True)

import input_conf_generator_lib as lib  # noqa: E402
import receive_process_payload as handler_mod  # noqa: E402


def payload(**overrides):
    base = {
        "message": "RFC123 - apache logs",
        "precedence": "low",
        "my_index": "web",
        "my_sourcetype": "access_combined",
        "my_source": ["/var/log/httpd/access.log"],
        "my_host": ["web01"],
        "additional_metadata": {"app_name": "apache", "environment": "prod", "version": "1.0.0", "requested_by": "jdoe"},
    }
    meta = overrides.pop("meta", {})
    base.update(overrides)
    base["additional_metadata"].update(meta)
    return base


class ValidationTests(unittest.TestCase):
    def assertRejected(self, p):
        with self.assertRaises(lib.ValidationError):
            lib.validate_payload(p)

    def test_valid(self):
        data = lib.validate_payload(payload())
        self.assertEqual(data["deployment_app"], "z_prod_web_apache")
        self.assertEqual(data["serverclass"], "z_prod_web_apache_web_access_combined")

    def test_higher_alias(self):
        self.assertEqual(lib.validate_payload(payload(precedence="higher"))["deployment_app"], "_prod_web_apache")

    def test_windows_path_ok(self):
        lib.validate_payload(payload(my_source=[r"C:\new\temp\app.log"]))

    def test_stanza_injection_rejected(self):
        self.assertRejected(payload(my_source=["/x]\n[script://./bin/evil.sh]\ninterval = 60"]))
        self.assertRejected(payload(my_index="web\n[batch:///etc]"))
        self.assertRejected(payload(my_host=["web01\nwhitelist.9 = *"]))

    def test_line_continuation_rejected(self):
        self.assertRejected(payload(my_source=["C:\\logs\\"]))

    def test_traversal_rejected(self):
        self.assertRejected(payload(meta={"app_name": "x/../../apps/pwn"}))
        self.assertRejected(payload(meta={"environment": ".."}))

    def test_wildcard_only_host_rejected(self):
        self.assertRejected(payload(my_host=["*"]))
        self.assertRejected(payload(my_host=["*.*"]))
        lib.validate_payload(payload(my_host=["web*"]))

    def test_empty_lists_rejected(self):
        self.assertRejected(payload(my_source=[""]))
        self.assertRejected(payload(my_host=[]))

    def test_relative_path_rejected(self):
        self.assertRejected(payload(my_source=["var/log/x.log"]))

    def test_message_flattened(self):
        self.assertEqual(lib.validate_payload(payload(message="a\nb"))["message"], "a b")


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())

    def read(self, *parts):
        return self.home.joinpath(*parts).read_text()

    def test_create_then_add_hosts_with_same_sources(self):
        lib.apply_payload(self.home, lib.validate_payload(payload()))
        inputs = self.read("etc", "deployment-apps", "z_prod_web_apache", "default", "inputs.conf")
        self.assertIn("[monitor:///var/log/httpd/access.log]\nindex = web\nsourcetype = access_combined", inputs)
        app_conf = self.read("etc", "deployment-apps", "z_prod_web_apache", "default", "app.conf")
        self.assertIn("[package]\nid = z_prod_web_apache", app_conf)

        # Same source, new host: inputs unchanged but host must still be added (old bug).
        r = lib.apply_payload(self.home, lib.validate_payload(payload(my_host=["web01", "web02"], meta={"version": "1.0.1"})))
        self.assertEqual(r["inputs_added"], [])
        self.assertEqual(r["hosts_added"], ["web02"])
        self.assertEqual(r["serverclass_status"], "updated")
        sc = self.read("etc", "apps", "input_conf_generator_serverclass", "local", "serverclass.conf")
        self.assertIn("whitelist.0 = web01", sc)
        self.assertIn("whitelist.1 = web02", sc)
        self.assertEqual(sc.count("[serverClass:z_prod_web_apache_web_access_combined]"), 1)
        self.assertEqual(sc.count(":app:z_prod_web_apache]"), 1)
        self.assertIn("version = 1.0.1", self.read("etc", "deployment-apps", "z_prod_web_apache", "default", "app.conf"))

        # Fully duplicate request is a no-op.
        r = lib.apply_payload(self.home, lib.validate_payload(payload(my_host=["web02"])))
        self.assertEqual(r["serverclass_status"], "unchanged")
        self.assertEqual(self.read("etc", "apps", "input_conf_generator_serverclass", "local", "serverclass.conf"), sc)

    def test_updates_existing_class_from_old_format(self):
        sc_path = self.home / "etc" / "apps" / "input_conf_generator_serverclass" / "local" / "serverclass.conf"
        sc_path.parent.mkdir(parents=True)
        sc_path.write_text(
            "\n# Added on x\n[serverClass:z_prod_web_apache_web_access_combined:app:z_prod_web_apache]\n"
            "restartSplunkWeb = 0\nrestartSplunkd = 1\nstateOnClient = enabled\n\n"
            "[serverClass:z_prod_web_apache_web_access_combined]\nwhitelist.0 = web01\n\n[serverClass:other]\nwhitelist.0 = x\n"
        )
        lib.apply_payload(self.home, lib.validate_payload(payload(my_host=["web03"])))
        text = sc_path.read_text()
        cls = text.split("[serverClass:z_prod_web_apache_web_access_combined]")[1].split("[serverClass:other]")[0]
        self.assertIn("whitelist.1 = web03", cls)
        self.assertEqual(text.count(":app:z_prod_web_apache]"), 1)


class HandlerTests(unittest.TestCase):
    def call(self, body, method="POST"):
        h = handler_mod.ReceivePayloadHandler("", "")
        return h.handle(json.dumps({"method": method, "payload": body, "session": {"user": "svc_sender"}}))

    def test_get_rejected(self):
        self.assertEqual(self.call("", method="GET")["status"], 405)

    def test_bad_json_is_400(self):
        self.assertEqual(self.call("not json")["status"], 400)

    def test_validation_errors_listed(self):
        r = self.call(json.dumps(payload(precedence="bogus", my_host=["*"])))
        self.assertEqual(r["status"], 400)
        self.assertEqual(len(r["payload"]["errors"]), 2)

    def test_dry_run_writes_nothing(self):
        p = payload(meta={"app_name": "dryrunapp"})
        p["dry_run"] = True
        r = self.call(json.dumps(p))
        self.assertEqual(r["status"], 200, r)
        self.assertTrue(r["payload"]["result"]["dry_run"])
        self.assertEqual(r["payload"]["result"]["inputs_added"], ["/var/log/httpd/access.log"])
        self.assertFalse(Path(TMP, "etc", "deployment-apps", "z_prod_web_dryrunapp").exists())

    def test_success(self):
        r = self.call(json.dumps(payload()))
        self.assertEqual(r["status"], 200, r)
        self.assertEqual(r["payload"]["result"]["inputs_added"], ["/var/log/httpd/access.log"])
        inputs = Path(TMP, "etc", "deployment-apps", "z_prod_web_apache", "default", "inputs.conf").read_text()
        self.assertIn("Requested by: jdoe (via svc_sender)", inputs)


if __name__ == "__main__":
    unittest.main()
