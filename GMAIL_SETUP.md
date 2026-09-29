# Email Configuration Guide for SecureVault AI

SecureVault AI uses a hybrid email delivery architecture:
1. **Registration Verification Codes**: Delivered via **Gmail SMTP** (`smtp.gmail.com`, port `465`, SSL).
2. **Password Reset Codes**: Delivered via **Resend HTTPS API** over HTTPS port 443.

---

## 1. Gmail SMTP Setup (Registration Verification)

Registration verification codes (6 digits, 10-minute expiry) are sent using Gmail's secure SMTP server over SSL.

### Step 1: Generate a Google App Password
1. Go to your [Google Account Security Settings](https://myaccount.google.com/security).
2. Ensure **2-Step Verification** is turned **ON**.
3. Go to [App Passwords](https://myaccount.google.com/apppasswords).
4. Enter an app name (e.g., `SecureVault AI`) and click **Create**.
5. Copy the generated 16-character password (e.g., `abcd efgh ijkl mnop`).

### Step 2: Configure Gmail Environment Variables

#### On Local Development (`.env`):
```ini
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=your-16-char-app-password
```

#### On Render / Cloud Hosting:
In your Render Dashboard:
1. Open your **SecureVault** Web Service.
2. Go to **Environment**.
3. Add the following environment variables:
   - `GMAIL_USER` = `your-email@gmail.com`
   - `GMAIL_APP_PASSWORD` = `your-16-char-app-password`
4. Click **Save Changes**. Render will automatically redeploy.

---

## 2. Resend Setup (Password Reset)

Password reset emails continue to use the **Resend HTTPS API** without changes.

### Environment Variables:
```ini
RESEND_API_KEY=re_your_api_key_here
MAIL_FROM=SecureVault AI <support@securevault.de5.net>
```

---

## 3. Summary of Environment Variables for Render

| Variable | Required For | Example Value | Description |
| :--- | :--- | :--- | :--- |
| **`GMAIL_USER`** | Registration verification | `yourname@gmail.com` | Your Gmail address used to authenticate and send verification codes |
| **`GMAIL_APP_PASSWORD`** | Registration verification | `abcdefghijklmnop` | 16-character Google App Password (spaces optional) |
| **`RESEND_API_KEY`** | Password reset | `re_123456789...` | API key from [Resend](https://resend.com/api-keys) |
| **`MAIL_FROM`** | Password reset | `SecureVault AI <support@...>` | Sender address verified in Resend |

---

## 4. Security & Architecture Details
- **SSL / Port 465**: Verification emails connect directly to `smtp.gmail.com:465` with explicit TLS/SSL context.
- **Credential Protection**: `GMAIL_APP_PASSWORD` and `RESEND_API_KEY` are read exclusively from environment variables and never logged or exposed.
- **Bcrypt Hashing**: All 6-digit codes are hashed with bcrypt before being stored in the database.
- **Brute-Force Protection**: 10-minute expiry and maximum 5 incorrect verification attempts per code.
