"""
Unit tests for Resend HTTPS API email delivery and failure handling in SecureVault.
"""
import unittest
from unittest.mock import patch, MagicMock
import os

from app import app, _send_verification_email, _send_reset_email
from db import get_db, init_db

class TestResendEmailDelivery(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

    def test_01_verification_email_missing_config(self):
        """When RESEND_API_KEY or MAIL_FROM is missing, should return False without crashing."""
        with patch.dict(os.environ, {'RESEND_API_KEY': '', 'MAIL_FROM': ''}, clear=False):
            with patch('app.RESEND_API_KEY', ''):
                with patch('app.MAIL_FROM', ''):
                    result = _send_verification_email('user@example.com', '123456')
                    self.assertFalse(result)

    def test_02_reset_email_missing_config(self):
        """When RESEND_API_KEY or MAIL_FROM is missing, reset email returns False."""
        with patch.dict(os.environ, {'RESEND_API_KEY': '', 'MAIL_FROM': ''}, clear=False):
            with patch('app.RESEND_API_KEY', ''):
                with patch('app.MAIL_FROM', ''):
                    result = _send_reset_email('user@example.com', '123456')
                    self.assertFalse(result)

    @patch('resend.Emails.send')
    def test_03_verification_email_success(self, mock_send):
        """When Resend succeeds, returns True and passes correct parameters."""
        mock_send.return_value = {'id': 'msg_test123'}
        with patch.dict(os.environ, {'RESEND_API_KEY': 're_testkey123', 'MAIL_FROM': 'onboarding@resend.dev'}):
            result = _send_verification_email('testuser@example.com', '654321')
            self.assertTrue(result)
            mock_send.assert_called_once()
            call_args = mock_send.call_args[0][0]
            self.assertEqual(call_args['from'], 'onboarding@resend.dev')
            self.assertEqual(call_args['to'], ['testuser@example.com'])
            self.assertEqual(call_args['subject'], 'Your SecureVault verification code')
            self.assertIn('654321', call_args['text'])
            self.assertIn('654321', call_args['html'])
            self.assertIn('Your verification code is: 654321', call_args['text'])

    @patch('resend.Emails.send')
    def test_04_reset_email_success(self, mock_send):
        """When Resend succeeds, returns True and passes correct parameters."""
        mock_send.return_value = {'id': 'msg_test456'}
        with patch.dict(os.environ, {'RESEND_API_KEY': 're_testkey123', 'MAIL_FROM': 'security@example.com'}):
            result = _send_reset_email('testuser@example.com', '789012')
            self.assertTrue(result)
            mock_send.assert_called_once()
            call_args = mock_send.call_args[0][0]
            self.assertEqual(call_args['from'], 'security@example.com')
            self.assertEqual(call_args['to'], ['testuser@example.com'])
            self.assertIn('Password Reset Code', call_args['subject'])
            self.assertIn('789012', call_args['text'])
            self.assertIn('789012', call_args['html'])

    @patch('resend.Emails.send')
    def test_05_verification_email_failure_exception(self, mock_send):
        """When Resend raises an exception, returns False and does not re-raise."""
        mock_send.side_effect = Exception("API connection timeout")
        with patch.dict(os.environ, {'RESEND_API_KEY': 're_testkey123', 'MAIL_FROM': 'onboarding@resend.dev'}):
            result = _send_verification_email('testuser@example.com', '123456')
            self.assertFalse(result)

    @patch('resend.Emails.send')
    def test_06_reset_email_failure_exception(self, mock_send):
        """When Resend raises an exception, returns False and does not re-raise."""
        mock_send.side_effect = Exception("Invalid API key")
        with patch.dict(os.environ, {'RESEND_API_KEY': 're_testkey123', 'MAIL_FROM': 'onboarding@resend.dev'}):
            result = _send_reset_email('testuser@example.com', '123456')
            self.assertFalse(result)

    @patch('app._send_verification_email', return_value=False)
    def test_07_registration_fails_gracefully_when_email_fails(self, mock_email):
        """If verification email delivery fails, registration redirects back with flash error and rolls back."""
        with app.app_context():
            init_db()
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM email_verification_codes WHERE email='resend_fail@example.com'")
            cur.execute("DELETE FROM users WHERE email='resend_fail@example.com'")
            db.commit()

        res = self.client.post('/register', data={
            'email': 'resend_fail@example.com',
            'name': 'Fail Test User',
            'password': 'SecurePassword123',
            'confirm_password': 'SecurePassword123',
            'agree_terms': 'on'
        }, follow_redirects=False)

        # Should redirect back to register
        self.assertEqual(res.status_code, 302)
        self.assertIn('/register', res.headers['Location'])

        # DB must NOT have committed the user or code (rolled back)
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT email FROM users WHERE email='resend_fail@example.com'")
            self.assertIsNone(cur.fetchone())

    @patch('app._send_verification_email', return_value=True)
    def test_08_registration_succeeds_when_email_succeeds(self, mock_email):
        """If verification email delivery succeeds, registration redirects to /verify-email."""
        with app.app_context():
            init_db()
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM email_verification_codes WHERE email='resend_ok@example.com'")
            cur.execute("DELETE FROM users WHERE email='resend_ok@example.com'")
            db.commit()

        res = self.client.post('/register', data={
            'email': 'resend_ok@example.com',
            'name': 'Success Test User',
            'password': 'SecurePassword123',
            'confirm_password': 'SecurePassword123',
            'agree_terms': 'on'
        }, follow_redirects=False)

        # Should redirect to verify-email
        self.assertEqual(res.status_code, 302)
        self.assertIn('/verify-email', res.headers['Location'])

        # DB must have committed unverified user
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT email, email_verified FROM users WHERE email='resend_ok@example.com'")
            u = cur.fetchone()
            self.assertIsNotNone(u)
            self.assertFalse(u['email_verified'])
            cur.execute("DELETE FROM email_verification_codes WHERE email='resend_ok@example.com'")
            cur.execute("DELETE FROM users WHERE email='resend_ok@example.com'")
            db.commit()

    @patch('resend.Emails.send')
    def test_09_api_key_whitespace_and_quote_stripping(self, mock_send):
        """API key and sender with spaces/quotes are cleanly stripped."""
        mock_send.return_value = {'id': 'msg_stripped'}
        with patch.dict(os.environ, {'RESEND_API_KEY': ' "re_spacedkey123" \n', 'MAIL_FROM': " 'onboarding@resend.dev' "}):
            import resend
            result = _send_verification_email('testuser@example.com', '123456')
            self.assertTrue(result)
            self.assertEqual(resend.api_key, 're_spacedkey123')
            self.assertEqual(mock_send.call_args[0][0]['from'], 'onboarding@resend.dev')

    def test_10_resend_error_safe_logging_and_redaction(self):
        """API keys are never logged in clear text even if present in Resend exceptions."""
        from app import _safe_log_resend_error
        import resend.exceptions as ex
        fake_key = 're_1234567890abcdef'
        fake_exc = ex.ResendError(
            code=403,
            error_type="restricted_api_key",
            message=f"Key {fake_key} cannot send to recipient",
            suggested_action=f"Verify domain or use valid key {fake_key}"
        )
        with self.assertLogs('app', level='ERROR') as cm:
            clean_msg = _safe_log_resend_error(fake_exc, api_key=fake_key)
            self.assertNotIn(fake_key, cm.output[0])
            self.assertIn('[REDACTED_API_KEY]', cm.output[0])
            self.assertIn('restricted_api_key', cm.output[0])
            self.assertIn('403', cm.output[0])

    @patch('app._send_verification_email', return_value=False)
    def test_11_registration_flash_surfaces_clear_error(self, mock_email):
        """Registration failure flash shows clear reason."""
        import app as app_mod
        app_mod._last_email_error = "The from field must be an email address from a verified domain or onboarding@resend.dev."
        res = self.client.post('/register', data={
            'email': 'resend_reason_test@example.com',
            'name': 'Reason Test',
            'password': 'SecurePassword123',
            'confirm_password': 'SecurePassword123',
            'agree_terms': 'on'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'verified domain', res.data)

    @patch('resend.Emails.send')
    def test_12_verification_email_uses_securevault_sender_address(self, mock_send):
        """Verification emails use SecureVault AI <support@securevault.de5.net> by default."""
        mock_send.return_value = {'id': 'msg_sender_verify'}
        with patch.dict(os.environ, {'RESEND_API_KEY': 're_testkey123', 'MAIL_FROM': 'SecureVault AI <support@securevault.de5.net>'}):
            result = _send_verification_email('newuser@example.com', '456789')
            self.assertTrue(result)
            mock_send.assert_called_once()
            call_args = mock_send.call_args[0][0]
            self.assertEqual(call_args['from'], 'SecureVault AI <support@securevault.de5.net>')
            self.assertEqual(call_args['to'], ['newuser@example.com'])

    @patch('resend.Emails.send')
    def test_13_reset_email_uses_securevault_sender_address(self, mock_send):
        """Password reset emails use SecureVault AI <noreply@securevault.de5.net> by default."""
        mock_send.return_value = {'id': 'msg_sender_reset'}
        with patch.dict(os.environ, {'RESEND_API_KEY': 're_testkey123', 'MAIL_FROM': 'SecureVault AI <noreply@securevault.de5.net>'}):
            result = _send_reset_email('newuser@example.com', '987654')
            self.assertTrue(result)
            mock_send.assert_called_once()
            call_args = mock_send.call_args[0][0]
            self.assertEqual(call_args['from'], 'SecureVault AI <noreply@securevault.de5.net>')
            self.assertEqual(call_args['to'], ['newuser@example.com'])

if __name__ == '__main__':
    unittest.main()
