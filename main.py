import os
import re
import time
from collections import defaultdict
from datetime import datetime
import requests

# إعدادات التكامل (يُفضل استخدام متغيرات البيئة للأمان)
TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"

LOG_FILE_PATH = "/var/log/auth.log"  # مسار السجل الحقيقي في أنظمة لينكس

def follow_log_file(file_path):
    """مولد بيانات لمحاكاة أمر tail -f لقراءة الأسطر الجديدة لحظياً"""
    if not os.path.exists(file_path):
        print(f"[!] تحذير: ملف السجل غير موجود ({file_path}). يرجى التحقق من المسار.")
        return
        
    with open(file_path, "r") as f:
        f.seek(0, 2)  # الانتقال إلى نهاية الملف
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def check_abuseipdb(ip):
    """التحقق من سمعة عنوان الـ IP عبر منصة AbuseIPDB"""
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        return 0  # قيمة افتراضية في حال عدم توفر مفتاح API
        
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            return response.json()['data'].get('abuseConfidenceScore', 0)
    except Exception as e:
        print(f"[!] خطأ في الاتصال بـ AbuseIPDB: {e}")
    return 0

def send_telegram_alert(message):
    """إرسال تنبيه فوري عبر بوت تيليجرام"""
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN":
        print(f"[محاكاة تنبيه تيليجرام]:\n{message}")
        return
        
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"[!] فشل إرسال التنبيه عبر تيليجرام: {e}")

def run_soc_monitor(threshold=3):
    failed_attempts = defaultdict(int)
    pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")

    print(f"[*] بدء مراقبة السجلات الحية من: {LOG_FILE_PATH}")
    
    for log_line in follow_log_file(LOG_FILE_PATH):
        match = pattern.search(log_line)
        if match:
            user, ip = match.groups()
            failed_attempts[ip] += 1
            print(f"[-] رصد محاولة فاشلة للمستخدم '{user}' من IP: {ip} (العدد: {failed_attempts[ip]})")

            if failed_attempts[ip] >= threshold:
                # التحقق من السمعة الأمنية
                abuse_score = check_abuseipdb(ip)
                severity = "HIGH" if failed_attempts[ip] >= 5 or abuse_score > 50 else "MEDIUM"
                
                alert_msg = (
                    f"🚨 *تنبيه أمني عاجل (Tier 1 SOC)* 🚨\n\n"
                    f"• *نوع الهجوم:* هجوم تخمين (Brute-Force)\n"
                    f"• *عنوان المصدر:* `{ip}`\n"
                    f"• *عدد المحاولات:* {failed_attempts[ip]}\n"
                    f"• *مستوى الخطورة:* `{severity}`\n"
                    f"• *نسبة الخطورة في AbuseIPDB:* `{abuse_score}%`\n"
                    f"• *الإجراء الموصى به:* حظر الـ IP فوراً عبر جدار الحماية."
                )
                
                if severity == "HIGH":
                    send_telegram_alert(alert_msg)
                    # إعادة ضبط العد لمنع إغراق التنبيهات لنفس الـ IP مؤقتاً
                    failed_attempts[ip] = 0

if __name__ == "__main__":
    try:
        run_soc_monitor()
    except KeyboardInterrupt:
        print("\n[*] إيقاف نظام مراقبة SOC بواسطة المستخدم.")
             