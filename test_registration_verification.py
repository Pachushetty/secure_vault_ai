"""
Automated unit & integration test for Registration Email Verification in SecureVault.
"""
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
import bcrypt
from werkzeug.security import check_password_hash

from app import app
from db import get_db, init_db

class TestRegistrationEmailVerification(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        with app.app_context():
            init_db()
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM email_verification_codes WHERE email LIKE 'testreg_%@example.com'")
            cur.execute("DELETE FROM users WHERE email LIKE 'testreg_%@example.com'")
            db.commit()

    def tearDown(self):
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM email_verification_codes WHERE email LIKE 'testreg_%@example.com'")
            cur.execute("DELETE FROM users WHERE email LIKE 'testreg_%@example.com'")
            db.commit()

    @patch('app._send_verification_email', return_value=True)
    def test_01_registration_flow_and_verification(self, mock_email):
        email = "testreg_user1@example.com"
        password = "SecurePassword123"
        name = "New Verified User"

        # 1. Submit Registration
        res_reg = self.client.post('/register', data={
            'email': email,
            'name': name,
            'password': password,
            'confirm_password': password,
            'agree_terms': 'on'
        }, follow_redirects=True)
        self.assertEqual(res_reg.status_code, 200)
        self.assertIn(b'Verify your email', res_reg.data)

        # Check DB state: user exists but unverified
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT email, email_verified, password_hash FROM users WHERE email = %s", (email,))
            u = cur.fetchone()
            self.assertIsNotNone(u)
            self.assertFalse(u['email_verified'])
            self.assertTrue(check_password_hash(u['password_hash'], password))

            # Check verification code generated
            cur.execute("SELECT id, code_hash, used FROM email_verification_codes WHERE email = %s", (email,))
            code_row = cur.fetchone()
            self.assertIsNotNone(code_row)
            self.assertFalse(code_row['used'])

            # Set known code for testing
            known_code = "654321"
            known_hash = bcrypt.hashpw(known_code.encode(), bcrypt.gensalt()).decode()
            cur.execute("UPDATE email_verification_codes SET code_hash = %s WHERE id = %s", (known_hash, code_row['id']))
            db.commit()

        # 2. Try to login before verification (this regenerates a fresh code)
        res_login_unverified = self.client.post('/login', data={
            'email': email,
            'password': password
        }, follow_redirects=True)
        self.assertIn(b'Please verify your email before signing in', res_login_unverified.data)

        # Set known code on the latest active code row
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT id FROM email_verification_codes WHERE email = %s AND used = FALSE ORDER BY created_at DESC LIMIT 1", (email,))
            latest_row = cur.fetchone()
            self.assertIsNotNone(latest_row)
            known_code = "654321"
            known_hash = bcrypt.hashpw(known_code.encode(), bcrypt.gensalt()).decode()
            cur.execute("UPDATE email_verification_codes SET code_hash = %s WHERE id = %s", (known_hash, latest_row['id']))
            db.commit()

        # 3. Submit wrong verification code
        res_wrong = self.client.post('/verify-email', data={'code': '000000'}, follow_redirects=True)
        self.assertIn(b'Incorrect verification code', res_wrong.data)

        # 4. Submit correct verification code
        res_correct = self.client.post('/verify-email', data={'code': known_code}, follow_redirects=True)
        self.assertEqual(res_correct.status_code, 200)
        self.assertIn(b'Email verified successfully', res_correct.data)

        # 5. Check DB: user is now verified
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT email_verified FROM users WHERE email = %s", (email,))
            u = cur.fetchone()
            self.assertTrue(u['email_verified'])

        # 6. Login successfully after verification
        res_login_success = self.client.post('/login', data={
            'email': email,
            'password': password
        }, follow_redirects=True)
        self.assertEqual(res_login_success.status_code, 200)
        self.assertIn(b'Welcome back', res_login_success.data)

if __name__ == '__main__':
    unittest.main()
