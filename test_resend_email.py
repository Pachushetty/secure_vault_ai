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
            self.assertIn('Verify Your Email Address', call_args['subject'])
            self.assertIn('654321', call_args['text'])
            self.assertIn('654321', call_args['html'])

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

if __name__ == '__main__':
    unittest.main()
