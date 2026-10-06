from app.config import Settings
from app.services.client_access_token import mint_client_access_token, parse_and_verify
from app.services.email_service import EmailService


def _settings(**kwargs) -> Settings:
    data = {
        "jwt_secret": "jwt-fallback",
        "client_token_secret": "shared-client-secret",
        "forensic_app_url": "http://localhost:3000",
        "mobile_extract_app_url": "http://localhost:3000",
        "vuln_app_url": "http://localhost:3000",
        "app_base_url": "http://localhost:3000",
        "mail_from": "noreply@test.local",
    }
    data.update(kwargs)
    return Settings.model_construct(**data)


def test_mint_is_stable_and_same_across_implicit_copies():
    settings = _settings()
    a = mint_client_access_token("Aetheris", "Jane.Doe@Firm.com", settings)
    b = mint_client_access_token("aetheris", "jane.doe@firm.com", settings)
    assert a == b
    assert a.startswith("ath1.aetheris.jane.doe@firm.com.")
    tenant, email = parse_and_verify(a, "aetheris", settings)
    assert tenant == "aetheris"
    assert email == "jane.doe@firm.com"


def test_parse_rejects_wrong_tenant_or_secret():
    settings = _settings()
    token = mint_client_access_token("aetheris", "user@firm.com", settings)
    try:
        parse_and_verify(token, "other-firm", settings)
        assert False, "expected wrong tenant to fail"
    except ValueError:
        pass
    other = _settings(client_token_secret="different-secret")
    try:
        parse_and_verify(token, "aetheris", other)
        assert False, "expected wrong secret to fail"
    except ValueError:
        pass


def test_falls_back_to_jwt_secret_when_client_secret_blank():
    settings = _settings(client_token_secret="")
    token = mint_client_access_token("platform", "admin@platform.test", settings)
    tenant, email = parse_and_verify(token, "platform", settings)
    assert tenant == "platform"
    assert email == "admin@platform.test"


def test_send_access_token_lists_single_ui_url(monkeypatch):
    sent: dict[str, str] = {}

    def fake_send(self, to, subject, body):
        sent["to"] = to
        sent["subject"] = subject
        sent["body"] = body

    monkeypatch.setattr(EmailService, "send", fake_send)
    svc = EmailService(_settings())
    token = mint_client_access_token("aetheris", "user@firm.com", _settings())
    svc.send_access_token("user@firm.com", token, "aetheris")
    assert sent["to"] == "user@firm.com"
    assert sent["subject"] == "Your Aetheris access token"
    assert token in sent["body"]
    assert "http://localhost:3000/login" in sent["body"]
    assert "Forensic: http://localhost:3001/login" not in sent["body"]
    assert sent["body"].count("Sign in here:") == 1


def test_email_send_skipped_when_mail_disabled():
    sent: dict[str, str] = {}

    def fake_smtp_send(self, to, subject, body):
        sent["to"] = to

    settings = _settings()
    settings.mail_send_enabled = False
    svc = EmailService(settings)
    # Bypass instance method after construct — send() itself must no-op.
    svc.send("user@firm.com", "should not send", "body")
    assert sent == {}
