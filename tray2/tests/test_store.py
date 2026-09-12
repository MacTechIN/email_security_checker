from mailshield2 import paths
from mailshield2.scanner import ScanResult
from mailshield2.store import AUTH_OAUTH, FOLDER_AUTO_SENT, AccountSettings, CheckpointStore, IncidentLog, Settings


def test_settings_roundtrip(isolated_data_dir):
    settings = Settings(account=AccountSettings(email="a@gmail.com", imap_host="imap.gmail.com", auth_method=AUTH_OAUTH), autostart=False)
    settings.save()
    loaded = Settings.load()
    assert loaded.account.email == "a@gmail.com"
    assert loaded.account.auth_method == AUTH_OAUTH
    assert loaded.account.folders == ["INBOX", FOLDER_AUTO_SENT]
    assert loaded.autostart is False
    assert paths.settings_path().parent == isolated_data_dir / "MailShield2"


def test_settings_load_tolerates_corrupt_file():
    paths.settings_path().write_text("{not json", encoding="utf-8")
    assert Settings.load().account.configured is False


def test_checkpoint_roundtrip_and_persistence():
    store = CheckpointStore()
    assert store.get("a@x.com", "INBOX") is None
    store.set("A@X.com", "INBOX", 647019771, 39330)
    assert CheckpointStore().get("a@x.com", "INBOX") == (647019771, 39330)
    store.clear()
    assert CheckpointStore().get("a@x.com", "INBOX") is None


def test_incident_log_persists_and_filters():
    log = IncidentLog()
    log.append(ScanResult(folder="INBOX", uid=1, subject="a", sender="b", findings=[], risk="safe"))
    log.append(ScanResult(folder="INBOX", uid=2, subject="c", sender="d", findings=["x"], risk="high"))
    assert [item["uid"] for item in log.recent()] == [2]
    assert [item["uid"] for item in log.recent(risky_only=False)] == [2, 1]
    reloaded = IncidentLog()
    assert [item["uid"] for item in reloaded.recent()] == [2]
