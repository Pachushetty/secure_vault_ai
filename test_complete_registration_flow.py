"""
Verification script for complete registration flow:
Register -> verification email sent -> receive 6-digit code -> enter code -> account verified -> login.
"""
import unittest
from unittest.mock import patch
import bcrypt

from app import app
from db import get_db, init_db

class TestCompleteRegistrationFlow(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.test_email = "flowtest@securevault.de5.net"
        self.test_password = "SecurePassword123!"
        self.test_name = "SecureVault Tester"
        
        with app.app_context():
            init_db()
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM email_verification_codes WHERE email = %s", (self.test_email,))
            cur.execute("DELETE FROM users WHERE email = %s", (self.test_email,))
            db.commit()

    def tearDown(self):
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM email_verification_codes WHERE email = %s", (self.test_email,))
            cur.execute("DELETE FROM users WHERE email = %s", (self.test_email,))
            db.commit()

    def test_01_resend_email_without_api_key_reports_exact_error(self):
        """When RESEND_API_KEY is not configured locally, exact error is captured."""
        from app import _send_verification_email, _last_email_error
        res = _send_verification_email(self.test_email, "123456")
        self.assertFalse(res)
        import app as app_mod
        self.assertEqual(app_mod._last_email_error, "RESEND_API_KEY or MAIL_FROM is not configured")

    def test_02_registration_post_fails_with_exact_error_when_no_api_key(self):
        """Registration attempt without RESEND_API_KEY redirects with the exact configuration error."""
        res = self.client.post('/register', data={
            'email': self.test_email,
            'name': self.test_name,
            'password': self.test_password,
            'confirm_password': self.test_password,
            'agree_terms': 'on'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'Could not send verification email: RESEND_API_KEY or MAIL_FROM is not configured', res.data)

    @patch('resend.Emails.send')
    def test_03_full_registration_verification_login_flow(self, mock_send):
        """
        Tests the complete 6-step flow:
        1. Register -> verification email dispatched using 'SecureVault AI <noreply@securevault.de5.net>'
        2. Verification email sent successfully via Resend API
        3. Receive 6-digit code (inspected from dispatched email call and hashed code in DB)
        4. Enter code at /verify-email
        5. Account verified in database
        6. Login -> Authenticated session active -> Dashboard access
        """
        mock_send.return_value = {'id': 'msg_live_flow_test'}

        with patch.dict('os.environ', {'RESEND_API_KEY': 're_mock_test_key'}):
            # Step 1: Register
            res_reg = self.client.post('/register', data={
                'email': self.test_email,
                'name': self.test_name,
                'password': self.test_password,
                'confirm_password': self.test_password,
                'agree_terms': 'on'
            }, follow_redirects=False)

            # Redirects to /verify-email
            self.assertEqual(res_reg.status_code, 302)
            self.assertIn('/verify-email', res_reg.headers['Location'])

            # Step 2: Verification email sent via Resend with exact sender address
            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args[0][0]
            self.assertEqual(call_kwargs['from'], 'SecureVault AI <support@securevault.de5.net>')
            self.assertEqual(call_kwargs['to'], [self.test_email])
            self.assertEqual(call_kwargs['subject'], 'Your SecureVault verification code')

            # Step 3: Extract the 6-digit code dispatched to recipient
            import re
            match = re.search(r'Your verification code is:\s*(\d{6})', call_kwargs['text'])
            self.assertIsNotNone(match, "Dispatched email must contain the 6-digit code")
            six_digit_code = match.group(1)

            # Also verify code in DB is hashed and unverified
            with app.app_context():
                db = get_db()
                cur = db.cursor()
                cur.execute("SELECT code_hash, used FROM email_verification_codes WHERE email = %s", (self.test_email,))
                code_row = cur.fetchone()
                self.assertIsNotNone(code_row)
                self.assertFalse(code_row['used'])
                self.assertTrue(bcrypt.checkpw(six_digit_code.encode(), code_row['code_hash'].encode()))

                cur.execute("SELECT email_verified FROM users WHERE email = %s", (self.test_email,))
                user_row = cur.fetchone()
                self.assertFalse(user_row['email_verified'])

            # Step 4: Enter the 6-digit code
            res_verify = self.client.post('/verify-email', data={'code': six_digit_code}, follow_redirects=True)
            self.assertEqual(res_verify.status_code, 200)
            self.assertIn(b'Email verified successfully', res_verify.data)

            # Step 5: Check account verified in DB
            with app.app_context():
                db = get_db()
                cur = db.cursor()
                cur.execute("SELECT email_verified FROM users WHERE email = %s", (self.test_email,))
                user_row = cur.fetchone()
                self.assertTrue(user_row['email_verified'])

            # Step 6: Login
            res_login = self.client.post('/login', data={
                'email': self.test_email,
                'password': self.test_password
            }, follow_redirects=True)
            self.assertEqual(res_login.status_code, 200)
            self.assertIn(b'Welcome back', res_login.data)

            # Confirm access to dashboard
            res_dash = self.client.get('/dashboard')
            self.assertEqual(res_dash.status_code, 200)

if __name__ == '__main__':
    unittest.main()
