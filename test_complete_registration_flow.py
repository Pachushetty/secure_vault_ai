"""
Verification script for complete registration flow:
Register -> verification email sent -> receive 6-digit code -> enter code -> account verified -> login.
"""
import unittest
from unittest.mock import patch, MagicMock
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

    def test_01_gmail_smtp_without_credentials_reports_exact_error(self):
        """When GMAIL_USER or GMAIL_APP_PASSWORD is not configured locally, exact error is captured."""
        from app import _send_verification_email
        import os
        with patch.dict(os.environ, {'GMAIL_USER': '', 'GMAIL_APP_PASSWORD': ''}, clear=False):
            with patch('app.GMAIL_USER', ''):
                with patch('app.GMAIL_APP_PASSWORD', ''):
                    res = _send_verification_email(self.test_email, "123456")
                    self.assertFalse(res)
                    import app as app_mod
                    self.assertEqual(app_mod._last_email_error, "GMAIL_USER or GMAIL_APP_PASSWORD is not configured")

    def test_02_registration_post_fails_with_exact_error_when_no_credentials(self):
        """Registration attempt without Gmail SMTP credentials redirects with the exact configuration error."""
        import os
        with patch.dict(os.environ, {'GMAIL_USER': '', 'GMAIL_APP_PASSWORD': ''}, clear=False):
            with patch('app.GMAIL_USER', ''):
                with patch('app.GMAIL_APP_PASSWORD', ''):
                    res = self.client.post('/register', data={
                        'email': self.test_email,
                        'name': self.test_name,
                        'password': self.test_password,
                        'confirm_password': self.test_password,
                        'agree_terms': 'on'
                    }, follow_redirects=True)
                    self.assertEqual(res.status_code, 200)
                    self.assertIn(b'Could not send verification email: GMAIL_USER or GMAIL_APP_PASSWORD is not configured', res.data)

    @patch('smtplib.SMTP_SSL')
    def test_03_full_registration_verification_login_flow(self, mock_smtp_ssl):
        """
        Tests the complete 6-step flow:
        1. Register -> verification email dispatched via Gmail SMTP (smtp.gmail.com:465 SSL)
        2. Verification email sent successfully via SMTP_SSL
        3. Receive 6-digit code (inspected from dispatched email call and hashed code in DB)
        4. Enter code at /verify-email
        5. Account verified in database
        6. Login -> Authenticated session active -> Dashboard access
        """
        mock_server = MagicMock()
        mock_smtp_ssl.return_value.__enter__.return_value = mock_server

        with patch.dict('os.environ', {'GMAIL_USER': 'testvault@gmail.com', 'GMAIL_APP_PASSWORD': 'abcd efgh ijkl mnop'}):
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

            # Step 2: Verification email sent via Gmail SMTP on port 465 SSL
            mock_smtp_ssl.assert_called_once()
            args, kwargs = mock_smtp_ssl.call_args
            self.assertEqual(args[0], 'smtp.gmail.com')
            self.assertEqual(args[1], 465)
            self.assertIn('context', kwargs)
            mock_server.login.assert_called_once_with('testvault@gmail.com', 'abcdefghijklmnop')
            mock_server.sendmail.assert_called_once()
            send_args = mock_server.sendmail.call_args[0]
            self.assertEqual(send_args[0], 'testvault@gmail.com')
            self.assertEqual(send_args[1], [self.test_email])
            raw_msg = send_args[2]

            # Step 3: Extract the 6-digit code dispatched to recipient
            import email
            msg_obj = email.message_from_string(raw_msg)
            body_text = ""
            for part in msg_obj.walk():
                if part.get_content_type() == "text/plain":
                    body_text = part.get_payload(decode=True).decode("utf-8")

            import re
            match = re.search(r'Your verification code is:\s*(\d{6})', body_text)
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
