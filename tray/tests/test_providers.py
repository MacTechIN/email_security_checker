from mailshield_tray import providers
from mailshield_tray.store import AUTH_APP_PASSWORD, AUTH_OAUTH


def test_gmail_detected_with_oauth_default():
    provider = providers.detect("Someone@Gmail.com")
    assert provider is not None
    assert provider.imap_host == "imap.gmail.com"
    assert provider.supports_oauth
    assert provider.default_auth == AUTH_OAUTH


def test_naver_detected_without_oauth():
    provider = providers.detect("user@naver.com")
    assert provider is not None
    assert provider.imap_host == "imap.naver.com"
    assert not provider.supports_oauth
    assert provider.default_auth == AUTH_APP_PASSWORD


def test_unknown_domain_guesses_imap_prefix():
    assert providers.detect("user@company.example") is None
    assert providers.guess_host("user@company.example") == "imap.company.example"
    assert providers.guess_host("not-an-email") == ""
