import os
import json
import datetime
import webbrowser
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QTabWidget, QFileDialog, QProgressBar,
    QMessageBox, QTreeWidget, QTreeWidgetItem, QSplitter,
    QHeaderView, QScrollArea, QFormLayout, QMenu, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QColor, QTextCursor, QSyntaxHighlighter, QTextCharFormat

from scanner_core import perform_scan
from report_generator import generate_report
from utils import load_last_scan, save_last_scan

class ScannerThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    analysis_completed = pyqtSignal(dict, dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, repo_url, github_token, yara_rule_source):
        super().__init__()
        self.repo_url = repo_url
        self.github_token = github_token
        self.yara_rule_source = yara_rule_source
        self.running = True

    def run(self):
        try:
            self.status_updated.emit("Получение файлов из репозитория...")
            results, scores, files = perform_scan(self.repo_url, self.github_token, self.yara_rule_source)
            self.analysis_completed.emit(results, scores)
        except Exception as e:
            self.error_occurred.emit(f"Ошибка при сканировании: {str(e)}")

    def stop(self):
        self.running = False

class CodeScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Code Security Scanner")
        self.setGeometry(100, 100, 1400, 900)
        self.scanner_thread = None
        self.results = None
        self.scores = None
        self.config = self.load_config()
        
        self.init_ui()
        self.load_last_session()
        self.setup_styles()

    def load_config(self):
        if os.path.exists("config.json"):
            with open("config.json", "r") as f:
                return json.load(f)
        return {}

    def setup_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f6fa;
                font-family: 'Segoe UI';
            }
            QLabel {
                color: #2d3436;
                font-size: 14px;
            }
            QLineEdit, QTextEdit, QTableWidget {
                background-color: #ffffff;
                border: 2px solid #dcdde1;
                border-radius: 4px;
                padding: 8px;
                font-size: 14px;
            }
            QPushButton {
                background-color: #487eb0;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 20px;
                font-size: 14px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #40739e;
            }
            QPushButton:disabled {
                background-color: #7f8fa6;
            }
            QProgressBar {
                border: 2px solid #dcdde1;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #487eb0;
                width: 10px;
            }
            QTabWidget::pane {
                border-top: 2px solid #487eb0;
            }
            QTabBar::tab {
                background: #f5f6fa;
                padding: 10px;
                border: 1px solid #dcdde1;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                border-color: #487eb0;
            }
            QTreeWidget {
                background: #ffffff;
                border: 1px solid #dcdde1;
                font-size: 14px;
            }
        """)

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Header
        header = QLabel("Advanced Code Security Scanner")
        header.setFont(QFont("Arial", 24, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        # Input Section
        input_layout = QFormLayout()
        self.repo_input = QLineEdit()
        self.repo_input.setPlaceholderText("https://github.com/user/repo")
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("GitHub Personal Access Token (optional)")
        self.token_input.setEchoMode(QLineEdit.Password)
        input_layout.addRow("Repository URL:", self.repo_input)
        input_layout.addRow("Access Token:", self.token_input)
        layout.addLayout(input_layout)

        # Control Buttons
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        self.export_btn.setEnabled(False)
        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)
        layout.addLayout(btn_layout)

        # Progress
        self.progress = QProgressBar()
        self.progress.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.progress)

        # Results Display
        splitter = QSplitter(Qt.Horizontal)
        
        # Left Panel - Tree View
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["File", "Risk Level"])
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        
        # Right Panel - Tabs
        self.tabs = QTabWidget()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.tabs.addTab(self.details_text, "Details")
        self.tabs.addTab(self.stats_text, "Statistics")
        self.tabs.addTab(self.log_text, "Logs")

        splitter.addWidget(self.tree)
        splitter.addWidget(self.tabs)
        splitter.setSizes([300, 700])
        layout.addWidget(splitter)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def show_context_menu(self, position):
        menu = QMenu()
        open_file = menu.addAction("Open in Browser")
        open_file.triggered.connect(self.open_in_browser)
        menu.exec_(self.tree.viewport().mapToGlobal(position))

    def open_in_browser(self):
        item = self.tree.currentItem()
        if item and hasattr(item, "url"):
            webbrowser.open(item.url)

    def log_message(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.moveCursor(QTextCursor.End)

    def start_scan(self):
        repo_url = self.repo_input.text().strip()
        if not repo_url:
            QMessageBox.warning(self, "Error", "Please enter a repository URL")
            return
        
        self.log_message(f"Starting scan for repository: {repo_url}")
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.progress.setValue(0)

        yara_rules = self.config.get("yara_rules", "")
        self.scanner_thread = ScannerThread(
            repo_url,
            self.token_input.text().strip() or None,
            yara_rules
        )
        self.scanner_thread.progress_updated.connect(self.update_progress)
        self.scanner_thread.status_updated.connect(self.update_status)
        self.scanner_thread.analysis_completed.connect(self.handle_results)
        self.scanner_thread.error_occurred.connect(self.handle_error)
        self.scanner_thread.start()

    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.scanner_thread.quit()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log_message("Scan stopped by user")

    def update_progress(self, value):
        self.progress.setValue(value)

    def update_status(self, message):
        self.status_bar.showMessage(message)
        self.log_message(message)

    def handle_results(self, results, scores):
        self.results = results
        self.scores = scores
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.progress.setValue(100)
        self.display_results()
        self.log_message("Scan completed successfully")
        self.save_session()
        QMessageBox.information(self, "Success", "Code analysis completed")

    def display_results(self):
        self.tree.clear()
        for filename, score in self.scores.items():
            item = QTreeWidgetItem([filename, str(score)])
            item.setData(0, Qt.UserRole, filename)
            if score >= 70:
                item.setBackground(1, QColor("#ff7675"))
            elif score >= 40:
                item.setBackground(1, QColor("#fdcb6e"))
            else:
                item.setBackground(1, QColor("#55efc4"))
            self.tree.addTopLevelItem(item)

        # Update details and statistics
        self.update_details()
        self.update_statistics()

    def update_details(self):
        self.details_text.clear()
        for filename, data in self.results.items():
            self.details_text.append(f"File: {filename}\n{'-'*40}")
            for key, value in data.items():
                if isinstance(value, dict):
                    self.details_text.append(f"{key}:")
                    for subkey, subvalue in value.items():
                        self.details_text.append(f"  {subkey}: {subvalue}")
                else:
                    self.details_text.append(f"{key}: {value}")
            self.details_text.append("\n")

    def update_statistics(self):
        self.stats_text.clear()
        total_files = len(self.scores)
        avg_score = sum(self.scores.values()) / total_files if total_files > 0 else 0
        high_risk = sum(1 for s in self.scores.values() if s >= 70)
        
        stats = f"""
        Total Files Scanned: {total_files}
        Average Risk Score: {avg_score:.2f}
        High Risk Files: {high_risk}
        """
        self.stats_text.setPlainText(stats)

    def export_report(self):
        if not self.results or not self.scores:
            QMessageBox.warning(self, "Error", "No data to export")
            return
        
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "",
            "Excel Files (*.xlsx);;All Files (*)")
        
        if path:
            try:
                generate_report(self.results, self.scores, path)
                self.log_message(f"Report exported to {path}")
                QMessageBox.information(self, "Success", "Report generated successfully")
            except Exception as e:
                self.log_message(f"Export error: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    def save_session(self):
        session = {
            "repo_url": self.repo_input.text(),
            "token": self.token_input.text(),
            "results": self.results,
            "scores": self.scores
        }
        save_last_scan(session)

    def load_last_session(self):
        session = load_last_scan()
        if session:
            self.repo_input.setText(session.get("repo_url", ""))
            self.token_input.setText(session.get("token", ""))
            self.results = session.get("results")
            self.scores = session.get("scores")
            if self.results and self.scores:
                self.display_results()
                self.log_message("Previous session loaded")

    def handle_error(self, message):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setValue(0)
        self.log_message(f"Error: {message}")
        QMessageBox.critical(self, "Error", message)

if __name__ == "__main__":
    app = QApplication([])
    window = CodeScannerGUI()
    window.show()
    app.exec_()