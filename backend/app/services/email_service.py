import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.config import Settings, get_settings


logger = logging.getLogger(__name__)


class MailDeliveryError(RuntimeError):
    """Safe delivery failure; never contains passwords, message bodies or tokens."""


class EmailService:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    def send(self, to: str, subject: str, body: str) -> bool:
        cfg = self.settings
        if not cfg.mail_send_enabled:
            logger.warning("Mail send skipped (MAIL_SEND_ENABLED=false)")
            return False
        implicit_tls = cfg.mail_smtp_ssl if cfg.mail_smtp_ssl is not None else cfg.mail_port == 465
        # Authenticated submission on 587 requires TLS before credentials.
        starttls = not implicit_tls and (cfg.mail_smtp_starttls or (cfg.mail_port == 587 and cfg.mail_smtp_auth))
        if cfg.mail_smtp_auth and (not cfg.mail_username or not cfg.mail_password):
            raise MailDeliveryError("SMTP authentication requires a username and password.")
        if cfg.mail_port == 465 and not implicit_tls:
            raise MailDeliveryError("SMTP port 465 requires MAIL_SMTP_SSL=true.")
        msg = EmailMessage()
        msg["From"] = cfg.mail_from
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        context = ssl.create_default_context()
        # Retry only disconnects before DATA. Never replay an ambiguous submission.
        for attempt in range(2):
            smtp = None
            submitting = False
            stage = "connection"
            try:
                if implicit_tls:
                    smtp = smtplib.SMTP_SSL(cfg.mail_host, cfg.mail_port, timeout=30, context=context)
                else:
                    smtp = smtplib.SMTP(cfg.mail_host, cfg.mail_port, timeout=30)
                smtp.ehlo()
                if starttls:
                    stage = "STARTTLS"
                    smtp.starttls(context=context)
                    smtp.ehlo()
                if cfg.mail_smtp_auth:
                    stage = "authentication"
                    # Challenge/response works with servers rejecting inline AUTH responses.
                    smtp.login(cfg.mail_username, cfg.mail_password, initial_response_ok=False)
                stage = "submission"
                submitting = True
                refused = smtp.send_message(msg)
                if refused:
                    raise MailDeliveryError("SMTP rejected the recipient.")
                return True
            except smtplib.SMTPServerDisconnected as exc:
                if not submitting and attempt == 0:
                    logger.warning("SMTP disconnected during %s; retrying once before submission", stage)
                    continue
                raise MailDeliveryError(f"SMTP disconnected during {stage}; check server settings and policy.") from exc
            except smtplib.SMTPAuthenticationError as exc:
                raise MailDeliveryError("SMTP authentication rejected; check credentials or provider app password.") from exc
            except (smtplib.SMTPException, OSError) as exc:
                raise MailDeliveryError(f"SMTP failed during {stage}; check mail configuration and connectivity.") from exc
            finally:
                if smtp is not None:
                    # QUIT failure must not turn an accepted email into a retry/error.
                    try:
                        smtp.quit()
                    except (smtplib.SMTPException, OSError):
                        smtp.close()
        raise MailDeliveryError("SMTP delivery failed.")

    def _activate_link(self, tenant_slug: str, token: str) -> str:
        return f"{self.settings.app_base_url}/activate?tenant={tenant_slug}&token={token}"

    def _reset_link(self, tenant_slug: str, token: str | None = None) -> str:
        base = f"{self.settings.app_base_url}/reset-password?tenant={tenant_slug}"
        if token:
            return f"{base}&token={token}"
        return base

    def send_invite(self, to: str, token: str, tenant_slug: str, is_admin: bool = False) -> None:
        role_label = "Firm Administrator" if is_admin else "User"
        link = self._activate_link(tenant_slug, token)
        body = (
            f"You have been invited as a {role_label} on Aetheris.\n\n"
            f"Organization: {tenant_slug}\n"
            f"Email: {to}\n\n"
            f"Activate your account and set your password here:\n{link}\n\n"
            f"This link expires in 7 days.\n"
            f"If you did not expect this email, you can ignore it."
        )
        self.send(to, f"Activate your account — Aetheris ({tenant_slug})", body)

    def send_password_reset(self, to: str, token: str, tenant_slug: str) -> None:
        link = self._reset_link(tenant_slug, token)
        body = (
            f"A password reset was requested for your Aetheris account.\n\n"
            f"Organization: {tenant_slug}\n"
            f"Email: {to}\n\n"
            f"Reset your password here:\n{link}\n\n"
            f"If you did not request this, ignore this email. Your password will not change."
        )
        self.send(to, "Password reset request — Aetheris", body)

    def send_password_reset_confirmation(
        self,
        to: str,
        tenant_slug: str,
        *,
        activated: bool = False,
    ) -> None:
        login_url = f"{self.settings.app_base_url}/login?tenant={tenant_slug}&email={to}"
        if activated:
            subject = "Your account is now active — Aetheris"
            intro = "Your account has been activated and your password has been set."
        else:
            subject = "Your password was changed — Aetheris"
            intro = "Your password was changed successfully."

        body = (
            f"{intro}\n\n"
            f"Organization: {tenant_slug}\n"
            f"Email: {to}\n\n"
            f"Sign in here:\n{login_url}\n\n"
            f"If you did not make this change, contact your administrator immediately."
        )
        self.send(to, subject, body)

    def send_access_token(self, to: str, token: str, tenant_slug: str) -> None:
        login_q = f"?tenant={tenant_slug}&email={to}"
        ui = (self.settings.app_base_url or self.settings.forensic_app_url or "").strip().rstrip("/")
        login_url = f"{ui}/login{login_q}" if ui else f"/login{login_q}"
        body = (
            f"Your Aetheris access token is below. Use the same token in the web UI "
            f"and on the laptop scanner.\n\n"
            f"Organization: {tenant_slug}\n"
            f"Email: {to}\n\n"
            f"Access token:\n{token}\n\n"
            f"Sign in here:\n{login_url}\n\n"
            f"Paste this token on the login page, or when Start-Laptop asks for it.\n"
            f"If you did not request this, ignore this email."
        )
        if not self.settings.mail_send_enabled:
            raise MailDeliveryError("Access-token email is disabled on this service.")
        self.send(to, "Your Aetheris access token", body)
