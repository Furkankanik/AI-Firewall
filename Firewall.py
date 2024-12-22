from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QWidget, QHBoxLayout, QListWidget, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from collections import defaultdict
import time
import os
import joblib
import numpy as np
import logging
import socket
import sys
import pydivert

logging.basicConfig(
    filename="firewall_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_to_file(message, level="info"):
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)

class firewallWorker(QThread):
    log_signal = pyqtSignal(str, str, str)
    rules_Signal = pyqtSignal(str)

    PROTOCOL_MAP = {
        1: "ICMP", 2: "IGMP", 6: "TCP", 8: "EGP", 9: "IGP", 17: "UDP",
        41: "IPv6", 50: "ESP (Encapsulation Security Payload)", 51: "AH(Authentication Header)",
        58: "ICMPv6", 89: "OSPF (Open Shortest Path First)", 132: "SCTP (Stream Control Transmission Protocol)",
        112: "VRRP (Virtual Router Redundancy Protocol)", 137: "MPLS-in-IP", 143: "ETHER-IP", 255: "Experimental(Reserved)"
    }

    def __init__(self, rules, website_filter, log_area):
        super().__init__()
        self.rules = rules
        self.website_filter = website_filter
        self.log_area = log_area
        self.running = True
        self.traffic_tracker = defaultdict(list)
        self.blacklist = set()
        self.whitelist = ["127.0.0.1", "::1"]
        self.ip_cache = {}
        self.model = self.train_ai_model()

    def train_ai_model(self):
        data = [ 
            [10,15,6],
            [20, 35, 17],  
            [5, 10, 2],    
            [25, 40, 20],  
            [7, 12, 4],    
            [30, 50, 25]   
        ]
        labels = [0,1,0,1,0,1]

        X_train, X_test, y_train, y_test = train_test_split(data, labels, test_size=0.3, random_state=42)

        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        log_to_file(f"AI Model doğruluğu: {accuracy * 100:.2f}%", level="info")

        joblib.dump(model, "ai_firewall_model.pkl")
        log_to_file("AI Model başarıyla kaydedildi.", level="info")
        return model

    def analyze_traffic(self, features):
        prediction = self.model.predict([features])[0]
        return prediction

    def resolve_url_to_ip(self, url):
        if url in self.ip_cache:
            return self.ip_cache[url]
        try:
            ip = socket.gethostbyname(url)
            self.ip_cache[url] = ip
            return ip
        except socket.gaierror:
            return None

    def get_protocol_name(self, protocol):
        if isinstance(protocol, tuple):
            protocol = protocol[0]
        return self.PROTOCOL_MAP.get(protocol, f"Unknown({protocol})")

    def run(self):
        try:
            with pydivert.WinDivert("tcp or udp") as w:
                for packet in w:
                    if not self.running:
                        break

                    src_ip = packet.src_addr
                    dst_ip = packet.dst_addr
                    protocol = self.get_protocol_name(packet.protocol)
                    current_time = time.time()

                    if src_ip in self.whitelist:
                        w.send(packet)
                        continue
                    if src_ip in self.blacklist:
                        self.rules_Signal.emit(f"IP in blacklist: {src_ip}")
                        continue
                    
                    resolved_ip = self.resolve_url_to_ip(dst_ip)
                    if resolved_ip and resolved_ip in self.website_filter:
                        self.rules_Signal.emit(f"Blocked: {dst_ip} (website)")
                        log_to_file(f"Blocked website: {dst_ip}", level="warning")
                        continue

                    self.traffic_tracker[src_ip].append(current_time)
                    short_window = [ts for ts in self.traffic_tracker[src_ip] if current_time - ts <= 1]
                    long_window = [ts for ts in self.traffic_tracker[src_ip] if current_time - ts <= 10]
                    short_count = len(short_window)
                    long_count = len(long_window)

                    if short_count > 10000 or long_count > 50000:
                        self.rules_Signal.emit(f"DDOS Detected: {src_ip} short_count={short_count}, long_count={long_count}")
                        self.blacklist.add(src_ip)
                        log_to_file(f"DDOS Detected and Blocked: {src_ip}", level="warning")
                        continue

                    self.log_signal.emit(src_ip, dst_ip, protocol)
                    log_to_file(f"Packet: {src_ip}:{packet.src_port} -> {dst_ip}:{packet.dst_port}")

                    blocked = False
                    for rule in self.rules:
                        if "tcp" in rule and protocol.lower() == "tcp":
                            self.rules_Signal.emit("TCP Packet Blocked.")
                            blocked = True
                            break
                        elif "udp" in rule and protocol.lower() == "udp":
                            self.rules_Signal.emit("UDP Packet Blocked.")
                            blocked = True
                            break
                        if rule in f"{packet.src_addr}:{packet.src_port}" or rule in f"{packet.dst_addr}:{packet.dst_port}":
                            self.rules_Signal.emit(f"Packet Blocked: {rule}")
                            log_to_file(f"Rule Blocked: {rule}", level="warning")
                            blocked = True
                            break

                    if not blocked:
                        w.send(packet)

        except Exception as e:
            self.rules_Signal.emit(f"Error: {str(e)}")

    def stop(self):
        self.running = False

class firewallGui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.rules_Signal = pyqtSignal(str)
        self.setWindowTitle("Türk Güvenlik Ağ Analiz Sistemi")
        self.setWindowIcon(QIcon("Güvenlik-Sistemi.ico"))
        self.tema()
        screen = QApplication.primaryScreen()
        screen_size = screen.availableGeometry()
        self.resize(screen_size.width() // 2, screen_size.height() // 2)

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        layout = QVBoxLayout()

        self.start_button = QPushButton("Firewall Başlat")
        self.start_button.clicked.connect(self.start_firewall)
        self.stop_button = QPushButton("Firewall Durdur")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_firewall)

        rule_layout = QHBoxLayout()
        self.rule_label = QLabel("Kurallar:")
        self.rule_list = QListWidget()
        self.rule_input = QLineEdit()
        self.rule_input.setPlaceholderText("Port Veya IP Kuralı Girin (ör. 192.168.1.1:80)...")
        self.add_rule_button = QPushButton("Kural Ekle")
        self.add_rule_button.clicked.connect(self.add_rule)
        rule_layout.addWidget(self.rule_input)
        rule_layout.addWidget(self.add_rule_button)
        self.rule_delete_button = QPushButton("Seçili Kuralı Sil")
        self.rule_delete_button.clicked.connect(self.delete_rule)

        self.network_label = QLabel("AĞ trafiği:")
        self.log_area = QTableWidget()
        self.log_area.setColumnCount(3)
        self.log_area.setHorizontalHeaderLabels(["Kaynak", "Hedef", "Protokol"])
        self.log_area.setEditTriggers(QTableWidget.NoEditTriggers)
        header = self.log_area.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        self.rules_label = QLabel("Uygulanan Kurallar:")
        self.rules_area = QTextEdit()
        self.rules_area.setReadOnly(True)

        self.blocker_label = QLabel("Engellenen Web Siteleri:")
        self.blocker_list = QListWidget()

        website_layout = QHBoxLayout()
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("Engellenecek Web Sitesi URL'sini Girin(Örn: www.example.com)...")
        self.add_website_button = QPushButton("Web Sitesi Ekle")
        self.add_website_button.clicked.connect(self.add_Website)
        self.add_WebSite_Sil_button = QPushButton("Web Sitesi Sil")
        self.add_WebSite_Sil_button.clicked.connect(self.delete_WebSite)
        website_layout.addWidget(self.website_input)
        website_layout.addWidget(self.add_website_button)
        website_layout.addWidget(self.add_WebSite_Sil_button) 
        website_widget = QWidget()
        website_widget.setLayout(website_layout)

        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.rule_label)
        layout.addWidget(self.rule_list)
        layout.addLayout(rule_layout)
        layout.addWidget(self.rule_delete_button)
        layout.addWidget(self.network_label)
        layout.addWidget(self.log_area)
        layout.addWidget(self.rules_label)
        layout.addWidget(self.rules_area)
        layout.addWidget(self.blocker_label)
        layout.addWidget(self.blocker_list)

        layout.addWidget(website_widget)
        self.main_widget.setLayout(layout)

        self.firewall_worker = None
        self.rules = []
        self.website_filter = set()

    def add_to_traffic_table(self, src, dst, protocol):
        if self.log_area.rowCount() > 1000:
            self.log_area.clearContents()  
        row_position = self.log_area.rowCount()
        self.log_area.insertRow(row_position)
        self.log_area.setItem(row_position, 0, QTableWidgetItem(src))
        self.log_area.setItem(row_position, 1, QTableWidgetItem(dst))
        self.log_area.setItem(row_position, 2, QTableWidgetItem(protocol))

    def add_rule(self):
        rule = self.rule_input.text()
        if not rule:
            QMessageBox.warning(self, "Uyarı", "Geçerli Bir Kural Girin!")
            return
        self.rules.append(rule)
        self.rule_list.addItem(rule)
        self.rule_input.clear()

    def delete_rule(self):
        selected_items = self.rule_list.selectedItems()
        if not selected_items:
            return
        for item in selected_items:
            rule = item.text()
            self.rules.remove(rule)
            self.rule_list.takeItem(self.rule_list.row(item))

    def add_Website(self):
        website = self.website_input.text()
        if website:
            self.website_filter.add(website)
            self.blocker_list.addItem(website)
            self.website_input.clear()

    def delete_WebSite(self):
        selected_item = self.blocker_list.currentItem()
        if selected_item:
            website = selected_item.text()
            self.website_filter.remove(website)
            self.blocker_list.takeItem(self.blocker_list.row(selected_item))

    def start_firewall(self):
        self.firewall_worker = firewallWorker(self.rules, self.website_filter, self.add_to_traffic_table)
        self.firewall_worker.log_signal.connect(self.add_to_traffic_table)
        self.firewall_worker.rules_Signal.connect(self.rules_area.append)
        self.firewall_worker.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_firewall(self):
        if self.firewall_worker:
            self.firewall_worker.stop()
            self.firewall_worker.wait()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    def tema(self):
        style_sheet = """
            QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: "Arial";
                font-size: 14px;
            }
            QPushButton {
                background-color: #444444;
                color: #ffffff;
                border-radius: 10px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QHeaderView::section {
                background-color: black;
                color: white;  
            }
            QPushButton:pressed {
                background-color: #333333;
            }
            QTableWidget {
                background-color: #2e2e2e;
                color: #7E5CAD;
                border: 1px solid #7E5CAD;
            }
            QTableWidget::item {
                padding: 5px;
                color: #7E5CAD;
            }
            QLineEdit, QTextEdit {
                background-color: #333333;
                color: #ffffff;
                border: 1px solid #7E5CAD;
                padding: 5px;
            }
            QListWidget {
                background-color: #333333;
                color: #ffffff;
                border: 1px solid #7E5CAD;
                border-radius: 10px;
            }
            QLabel {
                color: #ffffff;
                font-size: 16px;
            }
        """
        self.setStyleSheet(style_sheet)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = firewallGui() 
    window.show() 
    sys.exit(app.exec_())  
