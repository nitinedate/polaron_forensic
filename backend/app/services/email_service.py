import smtplib
from email.message import EmailMessage

from app.config import Settings, get_settings


class EmailService:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    def send(self, to: str, subject: str, body: str) -> None:
        if not self.settings.mail_send_enabled:
            import logging

            logging.getLogger(__name__).warning(
                "Mail send skipped (MAIL_SEND_ENABLED=false): to=%s subject=%s",
                to,
                subject,
            )
            return
        msg = EmailMessage()
        msg["From"] = self.settings.mail_from
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(self.settings.mail_host, self.settings.mail_port, timeout=30) as smtp:
            if self.settings.mail_smtp_starttls:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
            if self.settings.mail_smtp_auth and self.settings.mail_username:
                smtp.login(self.settings.mail_username, self.settings.mail_password)
            smtp.send_message(msg)

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
        self.send(to, "Your Aetheris access token", body)
