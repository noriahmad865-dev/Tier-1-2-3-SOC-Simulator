import os
import re
import json
import time
import subprocess
from collections import defaultdict
from datetime import datetime
import requests

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QAction
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTextEdit, QTableWidget, QTableWidgetItem, QLabel,
    QLineEdit, QPushButton, QGroupBox, QFormLayout, QHeaderView, QMessageBox, QDialog, QMenu, QFileDialog
)

# محاولة استيراد Scapy لالتقاط الحزم
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# --- ورقة الأنماط العامة (Global Modern Dark Theme - QSS) ---
MODERN_DARK_STYLE = """
QWidget {
    background-color: #121212;
    color: #e0e0e0;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 13px;
}
QMainWindow { background-color: #121212; }
QTabWidget::pane { border: 1px solid #2d2d2d; background-color: #181818; border-radius: 6px; }
QTabBar::tab { background-color: #212121; color: #9e9e9e; padding: 10px 18px; margin-right: 2px; border-top-left-radius: 6px; border-top-right-radius: 6px; font-weight: 600; }
QTabBar::tab:selected { background-color: #181818; color: #64b5f6; border-bottom: 2px solid #64b5f6; }
QTabBar::tab:hover { background-color: #2c2c2c; color: #ffffff; }
QGroupBox { border: 1px solid #2d2d2d; border-radius: 8px; margin-top: 12px; padding-top: 16px; font-weight: bold; color: #90caf9; background-color: #181818; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QLineEdit { background-color: #212121; border: 1px solid #333333; border-radius: 5px; padding: 6px 10px; color: #ffffff; selection-background-color: #1565c0; }
QLineEdit:focus { border: 1px solid #64b5f6; }
QTableWidget { background-color: #181818; gridline-color: #2a2a2a; border: 1px solid #2d2d2d; border-radius: 6px; selection-background-color: #1f3a60; selection-color: #ffffff; }
QHeaderView::section { background-color: #212121; color: #b0bec5; padding: 8px; border: none; border-bottom: 1px solid #333333; font-weight: bold; }
QTextEdit { background-color: #181818; border: 1px solid #2d2d2d; border-radius: 6px; color: #a5d6a7; padding: 8px; }
"""

class ThreatReportDialog(QDialog):
    def __init__(self, alert_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("تقرير تحليل مصدر التهديد والأدلة الجنائية - Tier 2")
        self.resize(600, 450)
        self.init_ui(alert_data)

    def init_ui(self, data):
        layout = QVBoxLayout(self)
        header = QLabel("🔍 تقرير الأدلة الجنائية والتحقيق المعمق (Incident Forensics)")
        header.setStyleSheet("font-size: 15px; font-weight: bold; color: #ef5350; margin-bottom: 8px;")
        layout.addWidget(header)

        report_box = QTextEdit()
        report_box.setReadOnly(True)
        report_box.setStyleSheet("background-color: #0d0d0d; color: #ffccbc; font-family: 'Consolas', monospace; font-size: 12px; border-radius: 6px;")
        
        report_content = (
            f"==================================================\n"
            f" [!] سجل حادثة أمنية معتمدة (Tier 2 SOC Incident)\n"
            f"==================================================\n"
            f"• المحلل المسؤول: أحمد (Ahmad Noree)\n"
            f"• وقت الرصد: {data['timestamp']}\n"
            f"• مؤشر الاختراق الأساسي (IOC - IP): {data['ip']}\n"
            f"• منفذ الاتصال (Port): {data['port']}\n"
            f"• العملية المسؤولة: {data['process']}\n"
            f"• المستخدم المستهدف: {data['user']}\n"
            f"• عدد المحاولات: {data['count']}\n"
            f"• تقييم السمعة (AbuseIPDB): {data['score']}%\n"
            f"• الخطورة: {data['severity']}\n"
            f"--------------------------------------------------\n"
            f" [ حالة الاحتواء (Containment Status) ]\n"
            f" تم رصد الهجوم والتحقق من صحة البورت والعملية المرتبطة.\n"
            f" الإجراء الموصى به: تفعيل أمر العزل عبر جدار الحماية (UFW/Firewall).\n"
            f"=================================================="
        )
        report_box.setPlainText(report_content)
        layout.addWidget(report_box)

        close_btn = QPushButton("إغلاق التقرير")
        close_btn.setStyleSheet("QPushButton { background-color: #37474f; color: white; font-weight: bold; padding: 8px; border-radius: 5px; } QPushButton:hover { background-color: #455a64; }")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


class NmapScanWorker(QThread):
    """عامل خلفي لتنفيذ فحص المنافذ والشبكة عبر Nmap بدون تجميد الواجهة"""
    scan_output_signal = pyqtSignal(str)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):
        self.scan_output_signal.emit(f"[*] جاري بدء فحص النطاق/الآبي: {self.target} باستخدام Nmap...\n" + "—"*50)
        try:
            # تنفيذ فحص سريع للمنافذ والأجهزة الحية
            process = subprocess.Popen(
                ["nmap", "-T4", "-F", self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            for line in process.stdout:
                self.scan_output_signal.emit(line.strip())
            process.wait()
            self.scan_output_signal.emit("\n[+] اكتمل فحص الشبكة بنجاح.")
        except FileNotFoundError:
            self.scan_output_signal.emit("[!] خطأ: لم يتم العثور على أداة Nmap مثبتة أو غير مضافة إلى مسار النظام (PATH).")
        except Exception as e:
            self.scan_output_signal.emit(f"[!] حدث خطأ أثناء تنفيذ الفحص: {e}")


class NetworkTrafficWorker(QThread):
    """عامل خلفي لتحليل حزم البيانات الحية عبر مكتبة Scapy"""
    packet_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        if not SCAPY_AVAILABLE:
            self.packet_signal.emit("[!] مكتبة Scapy غير مثبتة. يرجى تثبيتها عبر: pip install scapy")
            return

        self.packet_signal.emit("[*] بدء التقاط وتحليل حركة مرور الشبكة الحية (Network Traffic Sniffing)...\n" + "—"*50)

        def packet_callback(packet):
            if not self.running:
                return
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = "OTHER"
                sport, dport = "", ""
                
                if packet.haslayer(TCP):
                    proto = "TCP"
                    sport = str(packet[TCP].sport)
                    dport = str(packet[TCP].dport)
                elif packet.haslayer(UDP):
                    proto = "UDP"
                    sport = str(packet[UDP].sport)
                    dport = str(packet[UDP].dport)

                log_msg = f"[{datetime.now().strftime('%H:%M:%S')}] حزمة بيانات ({proto}) | المصدر: {src_ip}:{sport} ➔ الوجهة: {dst_ip}:{dport}"
                self.packet_signal.emit(log_msg)

        try:
            sniff(prn=packet_callback, store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.packet_signal.emit(f"[!] تنبيه في مراقبة الحزم (تأكد من تشغيل البرنامج بصلاحيات المسؤول وتثبيت Npcap): {e}")

    def stop(self):
        self.running = False


class SOCWorker(QThread):
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(dict)

    def __init__(self, log_file, api_key, bot_token, chat_id, threshold=3):
        super().__init__()
        self.log_file = log_file
        self.api_key = api_key
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.threshold = threshold
        self.running = True

    def run(self):
        failed_attempts = defaultdict(int)
        pattern = re.compile(r"(\S+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+\[\d+\]):\s+Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)(?:\s+port\s+(\d+))?")

        self.log_signal.emit(f"[*] بدء المراقبة الحية على الملف: {self.log_file}")

        if not os.path.exists(self.log_file):
            self.log_signal.emit(f"[!] تحذير: مسار السجل غير موجود. يتم تشغيل محاكاة بيئة العمل لاختبار الطبقات.")
            mock_lines = [
                "Sep  7 01:00:10 server sshd[1234]: Failed password for root from 192.168.1.50 port 54321 ssh2",
                "Sep  7 01:00:15 server sshd[1234]: Failed password for root from 192.168.1.50 port 54322 ssh2",
                "Sep  7 01:00:20 server sshd[1234]: Failed password for root from 192.168.1.50 port 54323 ssh2",
                "Sep  7 01:01:00 server sshd[1235]: Failed password for admin from 185.220.101.5 port 12345 ssh2",
                "Sep  7 01:01:05 server sshd[1235]: Failed password for admin from 185.220.101.5 port 12346 ssh2",
            ]
            for line in mock_lines:
                if not self.running:
                    break
                self.process_line(line, failed_attempts, pattern)
                time.sleep(1.5)
            return

        with open(self.log_file, "r") as f:
            f.seek(0, 2)
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                self.process_line(line.strip(), failed_attempts, pattern)

    def process_line(self, line, failed_attempts, pattern):
        self.log_signal.emit(line)
        match = pattern.search(line)
        if match:
            timestamp_raw, process, user, ip, port = match.groups()
            port = port if port else "Unknown"
            failed_attempts[ip] += 1
            count = failed_attempts[ip]

            if count >= self.threshold:
                abuse_score = self.check_abuseipdb(ip)
                severity = "HIGH" if count >= 5 or abuse_score > 50 else "MEDIUM"

                alert_data = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": ip,
                    "port": port,
                    "process": process,
                    "user": user,
                    "count": count,
                    "score": abuse_score,
                    "severity": severity
                }
                self.alert_signal.emit(alert_data)

                if severity == "HIGH" and self.bot_token and self.bot_token != "YOUR_BOT_TOKEN":
                    self.send_telegram(alert_data)
                    failed_attempts[ip] = 0

    def check_abuseipdb(self, ip):
        if not self.api_key or self.api_key == "YOUR_ABUSEIPDB_API_KEY":
            return 20
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': self.api_key, 'Accept': 'application/json'}
        try:
            res = requests.get(url, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'}, timeout=4)
            if res.status_code == 200:
                return res.json()['data'].get('abuseConfidenceScore', 0)
        except:
            pass
        return 0

    def send_telegram(self, alert):
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        msg = (
            f"🚨 *تنبيه SOC متقدم (Tier 2/3)* 🚨\n\n"
            f"• *العملية المسؤولة:* `{alert['process']}`\n"
            f"• *مؤشر الاختراق IP:* `{alert['ip']}:{alert['port']}`\n"
            f"• *المستخدم:* `{alert['user']}`\n"
            f"• *الخطورة:* `{alert['severity']}`"
        )
        try:
            requests.post(url, json={"chat_id": self.chat_id, "text": msg, "parse_mode": "Markdown"}, timeout=4)
        except:
            pass

    def stop(self):
        self.running = False


class SOCMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Tier 1-3 SOC Operations Center - Analyst: Ahmad")
        self.resize(1250, 820)
        self.worker = None
        self.nmap_worker = None
        self.traffic_worker = None
        self.alerts_store = []
        self.raw_logs_store = []
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)

        # شريط العنوان العلوي
        header_layout = QHBoxLayout()
        header_label = QLabel("🛡️ مركز عمليات الأمن السيبراني المتكامل (Tiers 1-3) — المحلل المسؤول: <span style='color: #64b5f6;'>أحمد (Ahmad Noree)</span>")
        header_label.setStyleSheet("font-size: 14px; color: #eceff1; padding: 10px 15px; background-color: #1a237e; border-radius: 6px; border-left: 4px solid #64b5f6;")
        header_layout.addWidget(header_label)
        main_layout.addLayout(header_layout)

        tabs = QTabWidget()
        
        # --- تبويب مركز التنبيهات والتحكم ---
        dashboard_tab = QWidget()
        dash_layout = QVBoxLayout(dashboard_tab)
        dash_layout.setSpacing(12)

        config_group = QGroupBox("⚙️ إعدادات الربط والتحكم بالنظام")
        form_layout = QFormLayout(config_group)
        form_layout.setSpacing(10)
        
        self.path_input = QLineEdit("/var/log/auth.log")
        self.apikey_input = QLineEdit("YOUR_ABUSEIPDB_API_KEY")
        self.bot_input = QLineEdit("YOUR_BOT_TOKEN")
        self.chat_input = QLineEdit("YOUR_CHAT_ID")

        form_layout.addRow("مسار السجل:", self.path_input)
        form_layout.addRow("مفتاح AbuseIPDB API:", self.apikey_input)
        form_layout.addRow("Telegram Bot Token:", self.bot_input)
        form_layout.addRow("Telegram Chat ID:", self.chat_input)
        dash_layout.addWidget(config_group)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ تشغيل نظام المراقبة الشامل")
        self.start_btn.setStyleSheet("QPushButton { background-color: #2e7d32; color: white; font-weight: bold; padding: 10px 18px; border-radius: 6px; border: none; } QPushButton:hover { background-color: #388e3c; } QPushButton:disabled { background-color: #263238; color: #546e7a; }")
        self.start_btn.clicked.connect(self.start_monitoring)

        self.stop_btn = QPushButton("⏹ إيقاف النظام")
        self.stop_btn.setStyleSheet("QPushButton { background-color: #c62828; color: white; font-weight: bold; padding: 10px 18px; border-radius: 6px; border: none; } QPushButton:hover { background-color: #d32f2f; } QPushButton:disabled { background-color: #263238; color: #546e7a; }")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_monitoring)

        self.export_btn = QPushButton("📤 تصدير تقرير الحوادث (JSON)")
        self.export_btn.setStyleSheet("QPushButton { background-color: #0277bd; color: white; font-weight: bold; padding: 10px 18px; border-radius: 6px; border: none; } QPushButton:hover { background-color: #0288d1; }")
        self.export_btn.clicked.connect(self.export_json_report)

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.export_btn)
        dash_layout.addLayout(btn_layout)

        # جدول التنبيهات
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["التوقيت", "العملية (Process)", "عنوان IP:Port", "المستخدم", "المحاولات", "نقاط AbuseIPDB", "الخطورة"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.doubleClicked.connect(self.open_threat_report)
        
        dash_layout.addWidget(QLabel("📊 <b>سجل الحوادث الأمنية الحية (انقر بزر الفأرة الأيمن للاستجابة أو التحقيق):</b>"))
        dash_layout.addWidget(self.table)
        tabs.addTab(dashboard_tab, " مركز العمليات (SOC)")

        # --- تبويب فحص المنافذ والشبكة (Port & Host Scanning - Nmap) ---
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        scan_layout.setSpacing(12)

        scan_box_layout = QHBoxLayout()
        self.target_input = QLineEdit("192.168.1.1")
        self.target_input.setPlaceholderText("أدخل عنوان الآبي أو نطاق الشبكة (مثل 192.168.1.0/24)...")
        
        scan_btn = QPushButton("بدء فحص الشبكة (Nmap Scan)")
        scan_btn.setStyleSheet("QPushButton { background-color: #00838f; color: white; font-weight: bold; padding: 8px 16px; border-radius: 5px; border: none; } QPushButton:hover { background-color: #00acc1; }")
        scan_btn.clicked.connect(self.run_nmap_scan)

        scan_box_layout.addWidget(QLabel("🌐 <b>الهدف / نطاق الشبكة:</b>"))
        scan_box_layout.addWidget(self.target_input)
        scan_box_layout.addWidget(scan_btn)
        scan_layout.addLayout(scan_box_layout)

        self.scan_results_box = QTextEdit()
        self.scan_results_box.setReadOnly(True)
        scan_layout.addWidget(QLabel("📋 <b>نتائج استطلاع البورتات والأجهزة النشطة:</b>"))
        scan_layout.addWidget(self.scan_results_box)
        tabs.addTab(scan_tab, " فحص الشبكة (Network Scan)")

        # --- تبويب مراقبة حركة المرور الحية (Network Traffic Analysis - Scapy) ---
        traffic_tab = QWidget()
        traffic_layout = QVBoxLayout(traffic_tab)
        traffic_layout.setSpacing(12)

        traffic_btn_layout = QHBoxLayout()
        self.start_traffic_btn = QPushButton("▶ بدء التقاط الحزم الحية (Start Sniffing)")
        self.start_traffic_btn.setStyleSheet("QPushButton { background-color: #2e7d32; color: white; font-weight: bold; padding: 8px 16px; border-radius: 5px; border: none; } QPushButton:hover { background-color: #388e3c; }")
        self.start_traffic_btn.clicked.connect(self.start_traffic_sniffing)

        self.stop_traffic_btn = QPushButton("⏹ إيقاف الالتقاط")
        self.stop_traffic_btn.setStyleSheet("QPushButton { background-color: #c62828; color: white; font-weight: bold; padding: 8px 16px; border-radius: 5px; border: none; } QPushButton:hover { background-color: #d32f2f; }")
        self.stop_traffic_btn.setEnabled(False)
        self.stop_traffic_btn.clicked.connect(self.stop_traffic_sniffing)

        traffic_btn_layout.addWidget(self.start_traffic_btn)
        traffic_btn_layout.addWidget(self.stop_traffic_btn)
        traffic_btn_layout.addStretch()
        traffic_layout.addLayout(traffic_btn_layout)

        self.traffic_results_box = QTextEdit()
        self.traffic_results_box.setReadOnly(True)
        traffic_layout.addWidget(QLabel("📡 <b>تحليل وحركة حزم البيانات الحية بين الأجهزة (Scapy Live Stream):</b>"))
        traffic_layout.addWidget(self.traffic_results_box)
        tabs.addTab(traffic_tab, " تحليل حركة المرور (Traffic Analysis)")

        # --- تبويب البحث والتحقيق (Threat Hunting) ---
        hunt_tab = QWidget()
        hunt_layout = QVBoxLayout(hunt_tab)
        hunt_layout.setSpacing(12)
        
        search_box_layout = QHBoxLayout()
        self.hunt_input = QLineEdit()
        self.hunt_input.setPlaceholderText("اكتب هنا للبحث عن IP أو مستخدم أو مؤشر اختراق IOC...")
        
        search_btn = QPushButton("بحث في السجلات التاريخية")
        search_btn.setStyleSheet("QPushButton { background-color: #37474f; color: white; font-weight: bold; padding: 8px 16px; border-radius: 5px; border: none; } QPushButton:hover { background-color: #455a64; }")
        search_btn.clicked.connect(self.run_ioc_hunt)
        
        search_box_layout.addWidget(QLabel("🔍 <b>استعلام مؤشرات الاختراق (IOC Search):</b>"))
        search_box_layout.addWidget(self.hunt_input)
        search_box_layout.addWidget(search_btn)
        hunt_layout.addLayout(search_box_layout)

        self.hunt_results_box = QTextEdit()
        self.hunt_results_box.setReadOnly(True)
        hunt_layout.addWidget(self.hunt_results_box)
        tabs.addTab(hunt_tab, " بحث التهديدات (Threat Hunting)")

        # --- تبويب السجلات الحية الخام ---
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        logs_layout.setSpacing(8)
        self.log_text_box = QTextEdit()
        self.log_text_box.setReadOnly(True)
        logs_layout.addWidget(QLabel("🖥️ <b>بث السجلات النظامية الخام (Live Log Stream):</b>"))
        logs_layout.addWidget(self.log_text_box)
        tabs.addTab(logs_tab, " مراقب السجلات (Log Streamer)")

        main_layout.addWidget(tabs)
        self.setCentralWidget(central_widget)

    def start_monitoring(self):
        log_path = self.path_input.text()
        api_key = self.apikey_input.text()
        bot_token = self.bot_input.text()
        chat_id = self.chat_input.text()

        self.worker = SOCWorker(log_path, api_key, bot_token, chat_id)
        self.worker.log_signal.connect(self.append_log)
        self.worker.alert_signal.connect(self.add_alert_to_table)
        self.worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.append_log("[*] تم تفعيل نظام رصد ومراقبة المستويات (1-3) بنجاح.")

    def stop_monitoring(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.append_log("[*] تم إيقاف النظام يدويًا.")

    def run_nmap_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "تنبيه", "يرجى إدخال عنوان آبي أو نطاق للشبكة.")
            return
        self.scan_results_box.clear()
        self.nmap_worker = NmapScanWorker(target)
        self.nmap_worker.scan_output_signal.connect(self.scan_results_box.append)
        self.nmap_worker.start()

    def start_traffic_sniffing(self):
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "خطأ", "مكتبة Scapy غير متوفرة. ثبتها عبر الأمر: pip install scapy")
            return
        self.traffic_results_box.clear()
        self.traffic_worker = NetworkTrafficWorker()
        self.traffic_worker.packet_signal.connect(self.traffic_results_box.append)
        self.traffic_worker.start()
        self.start_traffic_btn.setEnabled(False)
        self.stop_traffic_btn.setEnabled(True)

    def stop_traffic_sniffing(self):
        if self.traffic_worker:
            self.traffic_worker.stop()
            self.traffic_worker.wait()
        self.start_traffic_btn.setEnabled(True)
        self.stop_traffic_btn.setEnabled(False)
        self.traffic_results_box.append("\n[*] تم إيقاف مراقبة حركة المرور الحية.")

    def append_log(self, text):
        self.raw_logs_store.append(text)
        self.log_text_box.append(text)

    def add_alert_to_table(self, alert):
        self.alerts_store.append(alert)
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        self.table.setItem(row, 0, QTableWidgetItem(alert["timestamp"]))
        self.table.setItem(row, 1, QTableWidgetItem(alert["process"]))
        self.table.setItem(row, 2, QTableWidgetItem(f"{alert['ip']}:{alert['port']}"))
        self.table.setItem(row, 3, QTableWidgetItem(alert["user"]))
        self.table.setItem(row, 4, QTableWidgetItem(str(alert["count"])))
        self.table.setItem(row, 5, QTableWidgetItem(f"{alert['score']}%"))
        
        severity_item = QTableWidgetItem(alert["severity"])
        if alert["severity"] == "HIGH":
            severity_item.setBackground(QColor(60, 20, 20))
            severity_item.setForeground(QColor(255, 138, 128))
        else:
            severity_item.setBackground(QColor(60, 50, 15))
            severity_item.setForeground(QColor(255, 235, 59))
        self.table.setItem(row, 6, severity_item)

    def open_threat_report(self, index):
        row = index.row()
        if 0 <= row < len(self.alerts_store):
            dialog = ThreatReportDialog(self.alerts_store[row], self)
            dialog.exec()

    def show_context_menu(self, pos):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.alerts_store):
            return
        alert = self.alerts_store[row]
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #212121; color: #e0e0e0; border: 1px solid #333333; padding: 4px; } QMenu::item { padding: 8px 20px; border-radius: 4px; } QMenu::item:selected { background-color: #1565c0; color: #ffffff; }")

        action_report = QAction("🔍 عرض تقرير الأدلة الجنائية المعمق", self)
        action_verify = QAction("⚖️ التحقق السلوكي: هل هو تهديد فعلي؟", self)
        action_block = QAction("🛡️ عزل فوري وتوليد أمر الحظر (Firewall Containment)", self)

        action_report.triggered.connect(lambda: self.open_threat_report(self.table.model().index(row, 0)))
        action_verify.triggered.connect(lambda: self.verify_threat_nature(alert))
        action_block.triggered.connect(lambda: self.execute_containment_action(alert))

        menu.addAction(action_report)
        menu.addAction(action_verify)
        menu.addSeparator()
        menu.addAction(action_block)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def verify_threat_nature(self, alert):
        count = alert['count']
        score = alert['score']
        process = alert['process']
        if count >= 5 or score > 40:
            verdict = f"🚨 **تهديد فعلي مؤكد (Malicious Activity)**\n\nالعملية `{process}` تتعرض لمحاولات مصادقة مكثفة من مصدر مشبوه ({score}%)."
        else:
            verdict = f"⚠️ **نشاط محتمل أو فحص روتيني (Low Risk / Routine)**\n\nالمحاولات محدودة وتحت السيطرة ضمن سياق العملية `{process}`."
        QMessageBox.information(self, "تحليل الطبقة الثانية (Tier 2 Triage)", verdict)

    def execute_containment_action(self, alert):
        ip = alert['ip']
        containment_cmd = f"netsh advfirewall firewall add rule name=\"Block_{ip}\" dir=in action=block remoteip={ip}"
        QMessageBox.warning(
            self, 
            "عزل الحادث الأمني (Tier 2 Containment)", 
            f"تم اعتماد أمر العزل والحظر بواسطة المحلل: **أحمد**\n\n"
            f"• **عنوان المصدر المعزول:** `{ip}`\n"
            f"• **أمر التطبيق الفعلي على جدار حماية ويندوز:**\n`{containment_cmd}`\n\n"
            f"تم حظر المصدر بنجاح من الوصول."
        )

    def run_ioc_hunt(self):
        query = self.hunt_input.text().strip()
        if not query:
            QMessageBox.warning(self, "تنبيه", "يرجى إدخال قيمة للبحث (مثل عنوان IP أو مستخدم).")
            return
        self.hunt_results_box.clear()
        self.hunt_results_box.append(f"[*] جاري البحث عن مؤشر الاختراق (IOC): [{query}] في السجلات التاريخية...\n" + "—"*40)
        matches = [log for log in self.raw_logs_store if query in log]
        if matches:
            self.hunt_results_box.append(f"\n[+] تم العثور على ({len(matches)}) تطابق سياقي:\n")
            for m in matches:
                self.hunt_results_box.append(m)
        else:
            self.hunt_results_box.append("\n[-] لم يتم العثور على نتائج مطابقة لهذا المؤشر في نطاق السجلات الحالية.")

    def export_json_report(self):
        if not self.alerts_store:
            QMessageBox.information(self, "تنبيه", "لا توجد تنبيهات مسجلة لتصديرها حالياً.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "حفظ تقرير الحوادث", "soc_incident_report.json", "JSON Files (*.json)")
        if file_path:
            try:
                report_data = {
                    "analyst": "Ahmad Noree",
                    "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total_incidents": len(self.alerts_store),
                    "incidents": self.alerts_store
                }
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(report_data, f, indent=4, ensure_ascii=False)
                QMessageBox.information(self, "نجاح التصدير", f"تم حفظ التقرير الأمني بنجاح في:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "خطأ", f"فشل حفظ الملف: {e}")

    def closeEvent(self, event):
        if self.worker:
            self.worker.stop()
        if self.traffic_worker:
            self.traffic_worker.stop()
        event.accept()


if __name__ == "__main__":
    app = QApplication([])
    app.setStyleSheet(MODERN_DARK_STYLE)
    window = SOCMainWindow()
    window.show()
    app.exec()