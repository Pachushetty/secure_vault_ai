# Gmail SMTP Setup Guide for SecureVault Password Reset

SecureVault uses **Gmail SMTP** (`smtp.gmail.com:587` over TLS/STARTTLS) to send secure 6-digit verification codes for password recovery.

To keep your account secure, Google requires using a **16-character App Password** instead of your regular Gmail account password.

---

## Step-by-Step Setup Instructions

### Step 1: Enable 2-Step Verification on your Google Account
1. Open [Google Account Security](https://myaccount.google.com/security).
2. Under the **"How you sign in to Google"** section, click **2-Step Verification**.
3. Follow the on-screen instructions to turn it on (if not already enabled).

---

### Step 2: Generate a Google App Password
1. Navigate directly to [Google App Passwords](https://myaccount.google.com/apppasswords).
2. Enter an app name, e.g., `SecureVault`.
3. Click **Create**.
4. Google will display a **16-character password** (e.g. `abcd efgh ijkl mnop`).
5. Copy this 16-character string (without spaces).

---

### Step 3: Add Credentials to `.env`
Open your `.env` file in the root `vault/` directory and add your email and generated App Password:

```ini
MAIL_USERNAME=your_email@gmail.com
MAIL_APP_PASSWORD=abcdefghijklmnop
```

> **Security Note:** Never commit your `.env` file to Git. The `.gitignore` file is already configured to exclude `.env`.

---

### Step 4: Restart and Test
1. Restart your Flask development server:
   ```bash
   python app.py
   ```
2. Navigate to [http://localhost:5000/login](http://localhost:5000/login).
3. Click **Forgot password?**.
4. Enter your registered email address and submit.
5. Check your Gmail inbox for the SecureVault email with the 6-digit code.
6. Enter the code on the verification screen, create a new password, and log in.

---

## Security & Architecture Highlights
- **No Account Enumeration**: Submitting non-existent emails displays the exact same generic success message so attackers cannot probe for registered accounts.
- **Bcrypt-Hashed Verification Codes**: Reset codes are hashed with bcrypt before storing in PostgreSQL; plain codes are never saved in the database.
- **10-Minute Expiry**: Reset codes are automatically invalidated after 10 minutes.
- **Brute-Force Protection**: Rate limiting with Flask-Limiter and maximum 5 incorrect verification attempts per code.
- **Single-Use Codes**: Once verified, the reset code is flagged as used and cannot be replayed.
