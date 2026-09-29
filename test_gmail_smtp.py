"""
Unit tests for Gmail SMTP (SSL on port 465) registration verification email delivery.
"""
import unittest
from unittest.mock import patch, MagicMock
import os
import smtplib

from app import app, _send_verification_email, _safe_log_smtp_error
from db import get_db, init_db

class TestGmailSmtpDelivery(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

    def test_01_verification_email_missing_credentials(self):
        """When GMAIL_USER or GMAIL_APP_PASSWORD is missing, returns False without crashing."""
        with patch.dict(os.environ, {'GMAIL_USER': '', 'GMAIL_APP_PASSWORD': ''}, clear=False):
            with patch('app.GMAIL_USER', ''):
                with patch('app.GMAIL_APP_PASSWORD', ''):
                    result = _send_verification_email('user@example.com', '123456')
                    self.assertFalse(result)

    def test_02_verification_email_missing_password_only(self):
        """When GMAIL_APP_PASSWORD is missing, returns False."""
        with patch.dict(os.environ, {'GMAIL_USER': 'test@gmail.com', 'GMAIL_APP_PASSWORD': ''}, clear=False):
            with patch('app.GMAIL_USER', 'test@gmail.com'):
                with patch('app.GMAIL_APP_PASSWORD', ''):
                    result = _send_verification_email('user@example.com', '123456')
                    self.assertFalse(result)

    @patch('smtplib.SMTP_SSL')
    def test_03_verification_email_success(self, mock_smtp_ssl):
        """When Gmail SMTP succeeds, returns True and passes smtp.gmail.com, port 465, and SSL."""
        mock_server = MagicMock()
        mock_smtp_ssl.return_value.__enter__.return_value = mock_server

        with patch.dict(os.environ, {
            'GMAIL_USER': 'vault@gmail.com',
            'GMAIL_APP_PASSWORD': 'abcd efgh ijkl mnop'
        }):
            result = _send_verification_email('recipient@example.com', '654321')
            self.assertTrue(result)

            # Check server connection: smtp.gmail.com:465 with SSL context
            mock_smtp_ssl.assert_called_once()
            call_args, call_kwargs = mock_smtp_ssl.call_args
            self.assertEqual(call_args[0], 'smtp.gmail.com')
            self.assertEqual(call_args[1], 465)
            self.assertIn('context', call_kwargs)

            # Check login credentials (spaces stripped from Google App Password)
            mock_server.login.assert_called_once_with('vault@gmail.com', 'abcdefghijklmnop')

            # Check message dispatch
            mock_server.sendmail.assert_called_once()
            from_addr, to_addrs, raw_message = mock_server.sendmail.call_args[0]
            self.assertEqual(from_addr, 'vault@gmail.com')
            self.assertEqual(to_addrs, ['recipient@example.com'])
            self.assertIn('Subject: Your SecureVault verification code', raw_message)
            import email
            msg_obj = email.message_from_string(raw_message)
            body_text = ""
            for part in msg_obj.walk():
                if part.get_content_type() == "text/plain":
                    body_text = part.get_payload(decode=True).decode("utf-8")
            self.assertIn('654321', body_text)

    @patch('smtplib.SMTP_SSL')
    def test_04_verification_email_auth_failure(self, mock_smtp_ssl):
        """When SMTP authentication fails, returns False and sets helpful message."""
        mock_server = MagicMock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")
        mock_smtp_ssl.return_value.__enter__.return_value = mock_server

        with patch.dict(os.environ, {
            'GMAIL_USER': 'vault@gmail.com',
            'GMAIL_APP_PASSWORD': 'secretpassword12'
        }):
            result = _send_verification_email('recipient@example.com', '123456')
            self.assertFalse(result)
            import app as app_mod
            self.assertIn('authentication failed', app_mod._last_email_error)

    @patch('smtplib.SMTP_SSL')
    def test_05_verification_email_connection_error(self, mock_smtp_ssl):
        """When SMTP connection fails, returns False and does not crash."""
        mock_smtp_ssl.side_effect = smtplib.SMTPConnectError(421, "Connection refused")

        with patch.dict(os.environ, {
            'GMAIL_USER': 'vault@gmail.com',
            'GMAIL_APP_PASSWORD': 'secretpassword12'
        }):
            result = _send_verification_email('recipient@example.com', '123456')
            self.assertFalse(result)

    def test_06_smtp_error_safe_redaction(self):
        """Password is never logged in cleartext even if embedded in exception."""
        secret_pass = "supersecretapppass"
        exc = Exception(f"Failed with password {secret_pass} on smtp.gmail.com")
        clean = _safe_log_smtp_error(exc, password=secret_pass)
        self.assertNotIn(secret_pass, clean)
        self.assertIn("[REDACTED_PASSWORD]", clean)

if __name__ == '__main__':
    unittest.main()
