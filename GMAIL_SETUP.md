# Resend HTTPS API Setup Guide for SecureVault

SecureVault uses the **Resend HTTPS API** to deliver secure 6-digit verification codes for registration and password recovery over HTTPS.

This eliminates SMTP connection blocks on cloud hosting platforms such as **Render Free**, where outbound SMTP on port 587 or 465 is restricted.

---

## Step-by-Step Setup Instructions

### Step 1: Create a Resend Account & API Key
1. Go to [Resend](https://resend.com) and create an account.
2. Go to **API Keys** in the dashboard: [https://resend.com/api-keys](https://resend.com/api-keys).
3. Click **Create API Key**.
4. Give it a name (e.g., `SecureVault`) and copy the generated key (`re_...`).

---

### Step 2: Configure the Sender Address (`MAIL_FROM`)
- **For Initial Testing**: Resend allows sending from `onboarding@resend.dev` to the email address registered on your Resend account.
- **For Production / Custom Domains**:
  1. Go to **Domains** in your Resend dashboard: [https://resend.com/domains](https://resend.com/domains).
  2. Add your custom domain and configure the DNS records (DKIM/SPF).
  3. Once verified, use an address from your verified domain (e.g. `security@yourdomain.com`).

---

### Step 3: Configure Environment Variables

#### On Local Development (`.env`):
Add the variables to your `.env` file:

```ini
RESEND_API_KEY=re_your_api_key_here
MAIL_FROM=SecureVault AI <noreply@securevault.de5.net>
```

> **Security Note:** Never commit your `.env` file to Git. The `.gitignore` file excludes `.env`.

#### On Render / Cloud Hosting:
In your Render Dashboard:
1. Open your Web Service settings.
2. Navigate to **Environment**.
3. Add the environment variables:
   - `RESEND_API_KEY` = `re_...`
   - `MAIL_FROM` = `SecureVault AI <noreply@securevault.de5.net>`
4. Save changes. Render will automatically redeploy with the new settings.

---

### Step 4: Test Email Delivery
1. Start your application:
   ```bash
   python app.py
   ```
2. Navigate to [http://localhost:5000/register](http://localhost:5000/register) to create a test account or [http://localhost:5000/forgot-password](http://localhost:5000/forgot-password) to test password reset.
3. Check your recipient inbox for the 6-digit code.

---

## Security & Architecture Highlights
- **HTTPS Only**: All emails are sent via Resend's REST API over HTTPS port 443 — no SMTP connections required.
- **Credential Protection**: `RESEND_API_KEY` is kept server-side only and never exposed in frontend code, responses, or error logs.
- **No Account Enumeration**: Submitting non-existent emails displays the exact same generic success message so attackers cannot probe for registered accounts.
- **Bcrypt-Hashed Verification Codes**: Verification and reset codes are hashed with bcrypt before storing in PostgreSQL; plain codes are never saved in the database.
- **10-Minute Expiry**: Codes are automatically invalidated after 10 minutes.
- **Brute-Force Protection**: Rate limiting with Flask-Limiter and maximum 5 incorrect verification attempts per code.
- **Single-Use Codes**: Once verified, codes are flagged as used and cannot be replayed.
