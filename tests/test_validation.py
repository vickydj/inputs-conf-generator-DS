"""python3 -m unittest discover -s tests   (no Splunk needed)"""
import json, os, sys, tempfile, types, unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
for name in ("splunk", "splunk.persistconn", "splunk.persistconn.application", "splunk.rest"):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["splunk.persistconn.application"].PersistentServerConnectionApplication = object
sys.modules["splunk"].rest = sys.modules["splunk.rest"]
HOME = tempfile.mkdtemp()
os.environ["SPLUNK_HOME"] = HOME
os.makedirs(os.path.join(HOME, "var", "log", "splunk"))
import receive_process_payload  # noqa: E402
from receive_process_payload import MyRestHandler, validation_errors, PENDING_RELOAD  # noqa: E402
import reload_pending_serverclasses  # noqa: E402

OK = dict(index_name="web", message="RFC1", precedence="low", sourcetype="access_combined", app_name="apache",
          environment="prod", version="1.0.0", sources=["/var/log/a.log", r"C:\new\app.log"], hosts=["web01", "web*"])


class ValidationTests(unittest.TestCase):
    def errors(self, **change):
        return validation_errors(**dict(OK, **change))

    def test_valid_payload(self):
        self.assertEqual(self.errors(), [])

    def test_rejects_config_injection_and_traversal(self):
        for change in ({"sources": ["/x]\n[script://evil]"]}, {"sources": ["C:\\logs\\"]}, {"sources": ["relative.log"]},
                       {"index_name": "web\n[batch:///etc]"}, {"app_name": "x/../../apps/pwn"},
                       {"hosts": ["*"]}, {"hosts": ["web01\nwhitelist.9 = *"]}, {"precedence": "higher"},
                       {"message": "a\nb"}, {"sources": []},
                       {"submitted_by": "bob\n[monitor:///etc]"}, {"submitted_by": "bob\\"}):
            self.assertTrue(self.errors(**change), change)



class FakeDS:
    """In-memory stand-in for /deployment/server/serverclasses and /applications."""
    def __init__(self):
        self.classes, self.apps, self.calls = {}, {}, []

    def __call__(self, key, method, path, **args):
        self.calls.append((method, path, args))
        parts = path.strip("/").split("/")  # deployment, server, kind[, name]
        kind, name = parts[2], (parts[3] if len(parts) > 3 else args.get("name"))
        if kind == "serverclasses":
            if method == "GET":
                return (200, dict(self.classes[name])) if name in self.classes else (404, {})
            if len(parts) == 3 and name in self.classes:
                return 409, {}
            self.classes[name] = {k: v for k, v in args.items() if k.startswith("whitelist.")}
            return (201 if len(parts) == 3 else 200), {}
        if not Path(HOME, "etc", "deployment-apps", name).is_dir():
            return 404, {}
        app = self.apps.setdefault(name, {"serverclasses": []})
        if method == "POST":
            app["serverclasses"].append(args["serverclass"])
        return 200, dict(app)


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.ds = FakeDS()
        patcher = mock.patch.object(receive_process_payload, "ds_rest", self.ds)
        patcher.start()
        self.addCleanup(patcher.stop)

    def send(self, body):
        return MyRestHandler("", "").handle(json.dumps({"payload": json.dumps(body), "system_authtoken": "sys"}))

    def test_new_hosts_added_when_sources_already_exist(self):
        body = {"message": "RFC1", "precedence": "high", "my_index": "web", "my_sourcetype": "st",
                "my_source": ["/var/log/a.log"], "my_host": ["web01"],
                "additional_metadata": {"app_name": "apache", "environment": "prod", "version": "1.0.0"}}
        self.assertEqual(self.send(body)["status"], 200)
        body["my_host"] = ["web02"]
        self.assertEqual(self.send(body)["status"], 200)
        # a POST replaces the whitelist, so the update must carry the old host too
        self.assertEqual(self.ds.classes["_prod_web_apache_web_st"], {"whitelist.0": "web01", "whitelist.1": "web02"})
        self.assertEqual(self.ds.apps["_prod_web_apache"]["serverclasses"], ["_prod_web_apache_web_st"])

    def test_submitter_is_recorded_and_reload_queued(self):
        PENDING_RELOAD.unlink(missing_ok=True)
        body = {"message": "RFC3", "precedence": "normal", "my_index": "os", "my_sourcetype": "syslog",
                "my_source": ["/var/log/messages"], "my_host": ["db01"], "submitted_by": "alice",
                "additional_metadata": {"app_name": "linux", "environment": "qa"}}
        self.assertEqual(self.send(body)["status"], 200)
        inputs = Path(HOME, "etc", "deployment-apps", "y_qa_os_linux", "default", "inputs.conf").read_text()
        self.assertIn("Submitted by : alice", inputs)
        self.assertEqual(PENDING_RELOAD.read_text(), "y_qa_os_linux_os_syslog\n")
        # an unchanged resend queues nothing new
        self.send(body)
        self.assertEqual(PENDING_RELOAD.read_text(), "y_qa_os_linux_os_syslog\n")

    def test_resend_updates_version_in_app_conf(self):
        body = {"message": "RFC4", "precedence": "low", "my_index": "net", "my_sourcetype": "fw",
                "my_source": ["/var/log/fw.log"], "my_host": ["fw01"],
                "additional_metadata": {"app_name": "fw", "environment": "prod", "version": "1.0.0"}}
        self.send(body)
        body["additional_metadata"]["version"] = "1.2.0"
        self.send(body)
        app_conf = Path(HOME, "etc", "deployment-apps", "z_prod_net_fw", "default", "app.conf").read_text()
        self.assertIn("# Version: 1.2.0", app_conf)
        self.assertNotIn("# Version: 1.0.0", app_conf)

    def test_colon_in_sourcetype_is_safe_in_class_name(self):
        body = {"message": "RFC5", "precedence": "low", "my_index": "os", "my_sourcetype": "linux:audit",
                "my_source": ["/var/log/audit/audit.log"], "my_host": ["h1"],
                "additional_metadata": {"app_name": "audit", "environment": "prod"}}
        self.assertEqual(self.send(body)["status"], 200)
        self.assertIn("z_prod_os_audit_os_linux_audit", self.ds.classes)

    def test_ds_rest_failure_is_500(self):
        body = {"message": "RFC6", "precedence": "low", "my_index": "web", "my_sourcetype": "st",
                "my_source": ["/var/log/c.log"], "my_host": ["web09"],
                "additional_metadata": {"app_name": "restfail", "environment": "prod"}}
        with mock.patch.object(receive_process_payload, "ds_rest", return_value=(500, {})):
            result = self.send(body)
        self.assertEqual(result["status"], 500)
        self.assertIn("Write serverclass = failed", result["payload"]["Script_status"])

    def test_write_failure_is_reported(self):
        body = {"message": "RFC2", "precedence": "low", "my_index": "web", "my_sourcetype": "st",
                "my_source": ["/var/log/b.log"], "my_host": ["web03"],
                "additional_metadata": {"app_name": "broken", "environment": "prod"}}
        with mock.patch.object(MyRestHandler, "write_configs_to_file", return_value=False):
            result = self.send(body)
        self.assertEqual(result["status"], 500)
        self.assertEqual(result["payload"]["status"], "error")

    def test_bad_input_is_400(self):
        self.assertEqual(MyRestHandler("", "").handle(json.dumps({"payload": "not json"}))["status"], 400)
        self.assertEqual(self.send({"precedence": "higher"})["status"], 400)


class ReloadScriptTests(unittest.TestCase):
    def setUp(self):
        PENDING_RELOAD.parent.mkdir(parents=True, exist_ok=True)
        PENDING_RELOAD.write_text("a\nb\na\n")

    def run_with(self, statuses):
        calls = []

        def fake(path, sessionKey, method, postargs, getargs):
            calls.append(postargs.get("serverclass"))
            return types.SimpleNamespace(status=statuses[postargs["serverclass"]]), b""
        with mock.patch.object(reload_pending_serverclasses.splunk.rest, "simpleRequest", fake, create=True), \
                mock.patch("builtins.print"):
            failed = reload_pending_serverclasses.main("key")
        return calls, failed

    def test_reloads_each_class_once_and_clears_queue(self):
        calls, failed = self.run_with({"a": 200, "b": 200})
        self.assertEqual((calls, failed), (["a", "b"], []))
        self.assertFalse(PENDING_RELOAD.exists())

    def test_failed_classes_stay_queued(self):
        calls, failed = self.run_with({"a": 200, "b": 500})
        self.assertEqual(failed, ["b"])
        self.assertEqual(PENDING_RELOAD.read_text(), "b\n")
        self.assertFalse(PENDING_RELOAD.with_suffix(".processing").exists())


if __name__ == "__main__":
    unittest.main()
