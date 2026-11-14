"""python3 -m unittest discover -s tests   (no Splunk needed)"""
import json, os, sys, tempfile, types, unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
for name in ("splunk", "splunk.persistconn", "splunk.persistconn.application"):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["splunk.persistconn.application"].PersistentServerConnectionApplication = object
HOME = tempfile.mkdtemp()
os.environ["SPLUNK_HOME"] = HOME
os.makedirs(os.path.join(HOME, "var", "log", "splunk"))
from receive_process_payload import MyRestHandler, validation_errors  # noqa: E402

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
                       {"message": "a\nb"}, {"sources": []}):
            self.assertTrue(self.errors(**change), change)



class HandlerTests(unittest.TestCase):
    def send(self, body):
        return MyRestHandler("", "").handle(json.dumps({"payload": json.dumps(body)}))

    def test_new_hosts_added_when_sources_already_exist(self):
        body = {"message": "RFC1", "precedence": "high", "my_index": "web", "my_sourcetype": "st",
                "my_source": ["/var/log/a.log"], "my_host": ["web01"],
                "additional_metadata": {"app_name": "apache", "environment": "prod", "version": "1.0.0"}}
        self.assertEqual(self.send(body)["status"], 200)
        body["my_host"] = ["web02"]
        self.assertEqual(self.send(body)["status"], 200)
        sc = Path(HOME, "etc", "apps", "input_conf_generator_serverclass", "local", "serverclass.conf").read_text()
        self.assertIn("web01", sc)
        self.assertIn("web02", sc)

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


if __name__ == "__main__":
    unittest.main()
