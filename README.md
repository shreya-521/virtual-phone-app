# 📱 VirtualPhone — Secure Virtual Phone Generator & OTP Receiver

A modern, privacy-compliant, mobile and desktop responsive **Virtual Phone Number Generator & OTP Receiver Application**.
---

## 🌟 Key Features

* **Anti-Collision ITU-T & NANP Validation**: Generates E.164 standard formatted phone numbers using designated test ranges (`+1 NXX 555-01XX` for US/CA, `+44 7700 900XXX` for UK, `+49 1522 888XXXX` for Germany, `+91 99999 XXXXX` for India) so test numbers **never collide** with real assigned subscriber numbers.
* **Abuse & Rate Limiting Engine**:
  * **Free Tier**: 10 requests/min, 500 requests/day cap.
  * **Paid Pro Tier**: 100 requests/min.
  * **Automated Scraper Detection**: IPs exceeding 1,000 requests/hour trigger an automated temporary IP ban and HTTP 429 response.
* **Regex OTP Extractor**: Parses 4 to 8 digit verification codes from simulated incoming SMS messages (`/\b\d{4,8}\b/`) with 1-click clipboard copying.
* **DPDP Act 2023 & GDPR Privacy Compliance**: Includes a Cookie Consent banner, 1-click **"Purge All User Data"** erasure button, and a strict **Zero-Phone-Number Server Logging Policy**.
* **Security Headers**: Server middleware enforces `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`.
* **Responsive Crimson Theme**: Touch-optimized bottom navigation bar for mobile devices and a sidebar navigation drawer for desktop viewports.

---

## 🛠️ Tech Stack

* **Frontend**: HTML5, CSS3 (Vanilla Glassmorphism), JavaScript (ES6+), FontAwesome Icons, Google Fonts (*Dancing Script*, *Inter*, *JetBrains Mono*).
* **Backend**: Node.js, Express.js, Security Middleware (`helmet`-equivalent CSP/HSTS policies).
* **Validation & Security**: Zod-style server-side schema validation, XSS prevention via text nodes, Gitleaks pre-commit secret scanning.

---

## 🚀 Quick Start (Run Locally)

### 1. Clone the Repository
```bash
git clone https://github.com/shreya-521/virtual-phone-app.git
cd virtual-phone-app
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Start the Application Server
```bash
npm start
```

Open your browser and navigate to **`http://localhost:3000`**.

---

## 📱 Mobile Access (Wi-Fi)

To test the application on your mobile phone on the same Wi-Fi network:
1. Find your computer's local IP address (`ipconfig` on Windows or `ifconfig` on Mac/Linux).
2. Open your phone's browser and type: `http://<YOUR_LOCAL_IP>:3000` (e.g. `http://192.168.29.96:3000`).

---

## ⚖️ Disclaimer & Acceptable Use

Generated phone numbers are strictly for **development, automated QA testing, and demonstration purposes**. Do not use generated numbers for spam, fraud, illegal activity, or impersonation.

---

## 📄 License

This project is licensed under the MIT License.
