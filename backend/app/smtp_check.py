"""Check SMTP connectivity/authentication without sending email or printing secrets."""
import argparse
import smtplib
import ssl

from app.config import get_settings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authenticate', action='store_true', help='Also verify configured SMTP credentials')
    args = parser.parse_args()
    cfg = get_settings()
    implicit = cfg.mail_smtp_ssl if cfg.mail_smtp_ssl is not None else cfg.mail_port == 465
    tls = not implicit and (cfg.mail_smtp_starttls or (cfg.mail_port == 587 and cfg.mail_smtp_auth))
    print(f'Endpoint: {cfg.mail_host}:{cfg.mail_port}; transport: {"TLS" if implicit else "STARTTLS" if tls else "plain"}; auth enabled: {cfg.mail_smtp_auth}; mail enabled: {cfg.mail_send_enabled}')
    smtp = None
    stage = 'connection'
    try:
        if cfg.mail_port == 465 and not implicit:
            print('FAIL: port 465 requires MAIL_SMTP_SSL=true.')
            return 1
        ctx = ssl.create_default_context()
        if implicit:
            smtp = smtplib.SMTP_SSL(cfg.mail_host, cfg.mail_port, timeout=10, context=ctx)
        else:
            smtp = smtplib.SMTP(cfg.mail_host, cfg.mail_port, timeout=10)
        smtp.ehlo()
        if tls:
            stage = 'STARTTLS'
            smtp.starttls(context=ctx)
            smtp.ehlo()
        print('Connection and configured TLS checks passed.')
        if args.authenticate:
            stage = 'authentication'
            if cfg.mail_smtp_auth:
                if not cfg.mail_username or not cfg.mail_password:
                    print('FAIL: SMTP username/password missing.')
                    return 1
                smtp.login(cfg.mail_username, cfg.mail_password, initial_response_ok=False)
                print('Authentication passed.')
            else:
                print('Authentication is disabled; no credentials sent.')
        print('No email was sent. No credentials or access tokens were printed.')
        return 0
    except (smtplib.SMTPException, OSError) as exc:
        print(f'FAIL during {stage}: {type(exc).__name__}. Check provider settings, credentials, TLS and network policy.')
        return 1
    finally:
        if smtp is not None:
            smtp.close()


if __name__ == '__main__':
    raise SystemExit(main())
