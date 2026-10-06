import smtplib
from unittest.mock import MagicMock, Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.services.email_service import EmailService, MailDeliveryError


def config(**changes):
    opts = dict(_env_file=None, MAIL_HOST='smtp.example.test', MAIL_PORT=587,
                MAIL_USERNAME='sender@example.test', MAIL_PASSWORD='test-only-secret',
                MAIL_FROM='sender@example.test', MAIL_SMTP_AUTH=True,
                MAIL_SMTP_STARTTLS=True, MAIL_SEND_ENABLED=True)
    opts.update(changes)
    return Settings(**opts)


@pytest.fixture
def transport(monkeypatch):
    smtp = MagicMock()
    smtp.send_message.return_value = {}
    constructor = Mock(return_value=smtp)
    monkeypatch.setattr('app.services.email_service.smtplib.SMTP', constructor)
    ssl_constructor = Mock(return_value=smtp)
    monkeypatch.setattr('app.services.email_service.smtplib.SMTP_SSL', ssl_constructor)
    return smtp, constructor, ssl_constructor


def test_starttls_before_challenge_auth(transport):
    smtp, plain, secure = transport
    assert EmailService(config()).send('recipient@example.test', 'subject', 'body')
    names = [c[0] for c in smtp.method_calls]
    assert names == ['ehlo', 'starttls', 'ehlo', 'login', 'send_message', 'quit']
    assert smtp.login.call_args.kwargs == {'initial_response_ok': False}
    assert smtp.starttls.call_args.kwargs['context'].check_hostname
    secure.assert_not_called()


@pytest.mark.parametrize('explicit', [None, True])
def test_465_implicit_tls(transport, explicit):
    smtp, plain, secure = transport
    assert EmailService(config(MAIL_PORT=465, MAIL_SMTP_SSL=explicit)).send('r@example.test', 's', 'b')
    secure.assert_called_once()
    assert secure.call_args.kwargs['context'].check_hostname
    smtp.starttls.assert_not_called()
    plain.assert_not_called()


def test_587_authenticated_auto_upgrade(transport):
    smtp, _, _ = transport
    EmailService(config(MAIL_SMTP_STARTTLS=False)).send('r@example.test', 's', 'b')
    smtp.starttls.assert_called_once()


def test_mailhog_without_auth_or_tls(transport):
    smtp, _, _ = transport
    EmailService(config(MAIL_HOST='mailhog', MAIL_PORT=1025, MAIL_SMTP_AUTH=False,
                        MAIL_SMTP_STARTTLS=False, MAIL_USERNAME='', MAIL_PASSWORD='')).send('r@example.test','s','b')
    smtp.login.assert_not_called()
    smtp.starttls.assert_not_called()


def test_auth_disconnect_retries_only_before_data(transport):
    smtp, plain, _ = transport
    smtp.login.side_effect = [smtplib.SMTPServerDisconnected('closed'), None]
    assert EmailService(config()).send('r@example.test', 's', 'b')
    assert plain.call_count == 2
    smtp.send_message.assert_called_once()


def test_persistent_disconnect_bounded_and_safe(transport, caplog):
    smtp, plain, _ = transport
    smtp.login.side_effect = smtplib.SMTPServerDisconnected('test-only-secret')
    with pytest.raises(MailDeliveryError, match='authentication') as exc:
        EmailService(config()).send('r@example.test', 's', 'TOKEN-BODY')
    assert plain.call_count == 2
    smtp.send_message.assert_not_called()
    assert 'test-only-secret' not in str(exc.value) + caplog.text
    assert 'TOKEN-BODY' not in caplog.text


def test_disconnect_during_submission_never_replayed(transport):
    smtp, plain, _ = transport
    smtp.send_message.side_effect = smtplib.SMTPServerDisconnected('closed after DATA')
    with pytest.raises(MailDeliveryError, match='submission'):
        EmailService(config()).send('r@example.test', 's', 'b')
    assert plain.call_count == 1
    smtp.send_message.assert_called_once()


def test_quit_disconnect_after_accepted_mail_is_success(transport):
    smtp, plain, _ = transport
    smtp.quit.side_effect = smtplib.SMTPServerDisconnected('quit')
    assert EmailService(config()).send('r@example.test', 's', 'b')
    assert plain.call_count == 1
    smtp.close.assert_called_once()


def test_bad_credentials_not_retried(transport):
    smtp, plain, _ = transport
    smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b'bad password')
    with pytest.raises(MailDeliveryError, match='authentication rejected'):
        EmailService(config()).send('r@example.test', 's', 'b')
    assert plain.call_count == 1


@pytest.mark.parametrize('changes', [{'MAIL_PASSWORD':''}, {'MAIL_PORT':465,'MAIL_SMTP_SSL':False}])
def test_invalid_configuration_fails_before_connect(transport, changes):
    _, plain, secure = transport
    with pytest.raises(MailDeliveryError):
        EmailService(config(**changes)).send('r@example.test','s','b')
    plain.assert_not_called()
    secure.assert_not_called()


def test_disabled_access_token_email_is_failure(transport):
    service = EmailService(config(MAIL_SEND_ENABLED=False))
    assert service.send('r@example.test','s','b') is False
    with pytest.raises(MailDeliveryError, match='disabled'):
        service.send_access_token('r@example.test','TOKEN','tenant')


@pytest.fixture
def endpoint(monkeypatch):
    from app.routers import auth
    db = MagicMock()
    monkeypatch.setattr(auth, '_resolve_login_context', Mock(return_value=('platform', None)))
    monkeypatch.setattr(auth.auth_service, 'find_active_user_for_access_token', Mock(return_value=object()))
    monkeypatch.setattr(auth, 'token_request_allowed', Mock(return_value=True))
    monkeypatch.setattr(auth, 'mint_client_access_token', Mock(return_value='TEST-TOKEN'))
    send = Mock()
    monkeypatch.setattr(auth.email_service, 'send_access_token', send)
    app = FastAPI()
    app.include_router(auth.router)
    app.dependency_overrides[auth.get_db] = lambda: db
    with TestClient(app) as client:
        yield client, auth, db, send


def test_endpoint_returns_503_for_delivery_failure(endpoint):
    client, _, db, send = endpoint
    send.side_effect = MailDeliveryError('SMTP authentication rejected')
    response = client.post('/api/auth/request-access-token', json={'email':'user@example.test'})
    assert response.status_code == 503
    assert response.json()['detail']['error']['code'] == 'mail_delivery_failed'
    assert 'TEST-TOKEN' not in response.text
    db.rollback.assert_called_once()


def test_endpoint_success_and_unknown_remain_generic(endpoint):
    client, auth, _, send = endpoint
    success = client.post('/api/auth/request-access-token', json={'email':'user@example.test'})
    assert success.status_code == 200 and success.json() == {'ok': True}
    send.assert_called_once()
    send.reset_mock()
    auth.auth_service.find_active_user_for_access_token.return_value = None
    unknown = client.post('/api/auth/request-access-token', json={'email':'unknown@example.test'})
    assert unknown.status_code == 200 and unknown.json() == success.json()
    send.assert_not_called()


def test_endpoint_infrastructure_failure_not_success(endpoint):
    client, auth, db, _ = endpoint
    auth.auth_service.find_active_user_for_access_token.side_effect = RuntimeError('database unavailable')
    response = client.post('/api/auth/request-access-token', json={'email':'user@example.test'})
    assert response.status_code == 503
    assert response.json()['detail']['error']['code'] == 'token_request_unavailable'
    db.rollback.assert_called_once()


def test_real_smtp_challenge_auth_disconnect_then_retry():
    """Exercise smtplib over localhost sockets, without sending external mail."""
    import base64
    import socketserver
    import threading

    class Server(socketserver.TCPServer):
        allow_reuse_address = True
        attempts = 0
        messages = []
        auth_commands = []

    class Handler(socketserver.StreamRequestHandler):
        def reply(self, data):
            self.wfile.write(data + b'\r\n')
            self.wfile.flush()

        def handle(self):
            self.server.attempts += 1
            self.reply(b'220 localhost test SMTP')
            while True:
                line = self.rfile.readline().rstrip(b'\r\n')
                if not line:
                    return
                command = line.split(b' ', 1)[0].upper()
                if command == b'EHLO':
                    self.reply(b'250-localhost\r\n250 AUTH PLAIN')
                elif command == b'AUTH':
                    self.server.auth_commands.append(line)
                    if self.server.attempts == 1:
                        return
                    if line != b'AUTH PLAIN':
                        return
                    self.reply(b'334 ')
                    credentials = base64.b64decode(self.rfile.readline().strip())
                    if credentials != b'\x00sender@example.test\x00test-only-secret':
                        self.reply(b'535 incorrect credentials')
                    else:
                        self.reply(b'235 authenticated')
                elif command in (b'MAIL', b'RCPT'):
                    self.reply(b'250 OK')
                elif command == b'DATA':
                    self.reply(b'354 end with dot')
                    chunks = []
                    while True:
                        data = self.rfile.readline()
                        if data == b'.\r\n':
                            break
                        if not data:
                            return
                        chunks.append(data)
                    self.server.messages.append(b''.join(chunks))
                    self.reply(b'250 accepted')
                elif command == b'QUIT':
                    self.reply(b'221 bye')
                    return
                else:
                    self.reply(b'250 OK')

    with Server(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = config(MAIL_HOST='127.0.0.1', MAIL_PORT=server.server_address[1], MAIL_SMTP_STARTTLS=False)
            assert EmailService(cfg).send('recipient@example.test','Local test','Synthetic content only')
            assert server.attempts == 2
            assert server.auth_commands == [b'AUTH PLAIN', b'AUTH PLAIN']
            assert len(server.messages) == 1
            assert b'Synthetic content only' in server.messages[0]
        finally:
            server.shutdown()
            thread.join(timeout=3)


def test_tls_failure_never_sends_credentials(transport):
    import ssl
    smtp, plain, _ = transport
    smtp.starttls.side_effect = ssl.SSLCertVerificationError('certificate mismatch')
    with pytest.raises(MailDeliveryError, match='STARTTLS'):
        EmailService(config()).send('r@example.test','s','b')
    smtp.login.assert_not_called()
    smtp.send_message.assert_not_called()
    assert plain.call_count == 1


def test_recipient_refusal_is_failure(transport):
    smtp, plain, _ = transport
    smtp.send_message.return_value = {'r@example.test':(550,b'rejected')}
    with pytest.raises(MailDeliveryError, match='recipient'):
        EmailService(config()).send('r@example.test','s','b')
    assert plain.call_count == 1


def test_diagnostic_authenticates_without_sending(transport, monkeypatch, capsys):
    from app import smtp_check
    smtp, _, _ = transport
    monkeypatch.setattr(smtp_check, 'get_settings', lambda:config())
    monkeypatch.setattr('sys.argv', ['smtp_check','--authenticate'])
    assert smtp_check.main() == 0
    smtp.send_message.assert_not_called()
    output = capsys.readouterr().out
    assert 'Authentication passed' in output and 'test-only-secret' not in output
    assert 'sender@example.test' not in output


def test_diagnostic_errors_do_not_print_server_payload(transport, monkeypatch, capsys):
    from app import smtp_check
    smtp, _, _ = transport
    smtp.login.side_effect = smtplib.SMTPAuthenticationError(535,b'test-only-secret')
    monkeypatch.setattr(smtp_check, 'get_settings', lambda:config())
    monkeypatch.setattr('sys.argv', ['smtp_check','--authenticate'])
    assert smtp_check.main() == 1
    output = capsys.readouterr().out
    assert 'SMTPAuthenticationError' in output and 'test-only-secret' not in output
    smtp.send_message.assert_not_called()
