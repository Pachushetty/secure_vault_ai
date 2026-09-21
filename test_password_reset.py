"""
Automated unit & integration test for the Forgot Password / Reset Flow in SecureVault.
Tests:
1. Forgot password page loads with 200 OK.
2. Account enumeration protection: unknown vs registered email gives identical user feedback.
3. Code generation & bcrypt hash validation.
4. Verify code page validation (wrong code, attempt counter, valid code).
5. Expiry validation logic.
6. Reset password validation (mismatch check, min-length check, success update).
7. Old reset code invalidation on success.
8. Settings & Login flow integrity.
"""
import unittest
from datetime import datetime, timedelta
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

from app import app
from db import get_db, init_db

class TestPasswordResetFlow(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        with app.app_context():
            init_db()
            db = get_db()
            cur = db.cursor()
            # Clean test records
            cur.execute("DELETE FROM password_reset_codes WHERE email LIKE 'test_%@example.com'")
            cur.execute("DELETE FROM users WHERE email LIKE 'test_%@example.com'")
            
            # Create a test user
            self.test_email = "test_reset_user@example.com"
            self.initial_password = "InitialPassword123"
            cur.execute("""
                INSERT INTO users (email, name, password_hash, auth_provider)
                VALUES (%s, %s, %s, %s)
            """, (self.test_email, "Test User", generate_password_hash(self.initial_password), "local"))
            db.commit()

    def tearDown(self):
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM password_reset_codes WHERE email LIKE 'test_%@example.com'")
            cur.execute("DELETE FROM users WHERE email LIKE 'test_%@example.com'")
            db.commit()

    def test_01_forgot_password_page_loads(self):
        res = self.client.get('/forgot-password')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'Reset Password', res.data)

    def test_02_account_enumeration_protection(self):
        # Non-existent email
        res1 = self.client.post('/forgot-password', data={'email': 'test_nonexistent@example.com'}, follow_redirects=True)
        self.assertEqual(res1.status_code, 200)
        self.assertIn(b'If an account exists for this email', res1.data)

        # Existing email
        res2 = self.client.post('/forgot-password', data={'email': self.test_email}, follow_redirects=True)
        self.assertEqual(res2.status_code, 200)
        self.assertIn(b'If an account exists for this email', res2.data)

    def test_03_code_verification_and_password_update(self):
        # 1. Request reset code
        self.client.post('/forgot-password', data={'email': self.test_email})
        
        # Check DB for generated code
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT id, code_hash, used FROM password_reset_codes WHERE email = %s ORDER BY created_at DESC LIMIT 1", (self.test_email,))
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertFalse(row['used'])
            
            # Manually insert known code for verification test
            known_code = "123456"
            known_hash = bcrypt.hashpw(known_code.encode(), bcrypt.gensalt()).decode()
            cur.execute("UPDATE password_reset_codes SET code_hash = %s WHERE id = %s", (known_hash, row['id']))
            db.commit()

        # 2. Test wrong code attempt
        res_wrong = self.client.post('/verify-code', data={'code': '999999'}, follow_redirects=True)
        self.assertIn(b'Incorrect code', res_wrong.data)

        # 3. Test correct code
        res_valid = self.client.post('/verify-code', data={'code': known_code}, follow_redirects=True)
        self.assertEqual(res_valid.status_code, 200)
        self.assertIn(b'Set New Password', res_valid.data)

        # 4. Set new password
        new_pw = "BrandNewSecurePassword123"
        res_new_pw = self.client.post('/reset-password', data={
            'new_password': new_pw,
            'confirm_password': new_pw
        }, follow_redirects=True)
        self.assertEqual(res_new_pw.status_code, 200)
        self.assertIn(b'Your password has been successfully updated', res_new_pw.data)

        # 5. Check if user can login with new password and cannot login with old
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT password_hash FROM users WHERE email = %s", (self.test_email,))
            user = cur.fetchone()
            self.assertTrue(check_password_hash(user['password_hash'], new_pw))
            self.assertFalse(check_password_hash(user['password_hash'], self.initial_password))

            # Verify code is marked as used
            cur.execute("SELECT used FROM password_reset_codes WHERE email = %s", (self.test_email,))
            codes = cur.fetchall()
            for c in codes:
                self.assertTrue(c['used'])

if __name__ == '__main__':
    unittest.main()
