# Unauthorized Access Detection Script

## 📌 Overview
This Python script analyzes server access logs to detect **potential unauthorized login attempts**.  
It checks for:
- Logins from **unapproved countries** per user.
- **Multiple failed login attempts** from the same user/IP (default: 3+ fails).

It then saves the findings in a **timestamped JSON report** for review.

---

## ⚙️ Features
- Parses log lines to extract:
  - Date & time
  - IP address
  - Username
  - Action (`LOGIN_SUCCESS` / `LOGIN_FAIL`)
- Maps IP addresses to countries (mock data included — can be replaced with real IP geolocation).
- Flags:
  - Successful logins from **unapproved locations**.
  - **Repeated failed login attempts**.
- Saves results in a readable **JSON file**.

---

## 📂 Log Format Example
The script expects each line in `access.log` to look like:

```
YYYY-MM-DD HH:MM:SS IP=IP_ADDRESS USER=USERNAME ACTION=ACTION_TYPE
```

Example:
```
2025-08-14 10:15:00 IP=192.168.1.5 USER=john ACTION=LOGIN_FAIL
2025-08-14 10:16:10 IP=192.168.1.5 USER=john ACTION=LOGIN_SUCCESS
```

---

## 🚀 How to Run

1. **Clone this repository**
   ```bash
   git clone https://github.com/yourusername/unauthorized-access-detector.git
   cd unauthorized-access-detector
   ```

2. **Make sure you have Python 3 installed**
   ```bash
   python --version
   ```

3. **Prepare your access log**
   - Place your log file in the same directory as the script.
   - Name it `access.log` (or change the `log_file` variable in the script).

4. **Run the script**
   ```bash
   python script_name.py
   ```
   Replace `script_name.py` with the actual filename.

5. **View the results**
   - A JSON file named like `Unauth_Access_YYYYMMDD_HHMM.json` will be created.
   - Open it in any text editor or JSON viewer to see flagged activity.

---
