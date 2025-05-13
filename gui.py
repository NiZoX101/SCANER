import os
import json
import datetime
import webbrowser
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QTabWidget, QFileDialog, QProgressBar,
    QMessageBox, QTreeWidget, QTreeWidgetItem, QSplitter,
    QHeaderView, QScrollArea, QFormLayout, QMenu, QStatusBar,
    QCheckBox, QGroupBox, QComboBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QColor, QTextCursor, QTextCharFormat

from scanner_core import perform_scan
from report_generator import generate_detailed_report
from utils import load_last_scan, save_last_scan
from heuristics import detailed_extract_suspicious_lines

class ScannerThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    analysis_completed = pyqtSignal(dict, dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, repo_url, github_token, yara_rule_source, check_types):
        super().__init__()
        self.repo_url = repo_url
        self.github_token = github_token
        self.yara_rule_source = yara_rule_source
        self.check_types = check_types
        self.running = True

    def run(self):
        try:
            self.status_updated.emit("Получение файлов из репозитория...")
            results, scores, files = perform_scan(
                self.repo_url, self.github_token, self.yara_rule_source, self.check_types
            )
            self.progress_updated.emit(100)
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
        self.check_types = ["ast", "regex", "yara", "bandit", "heuristics"]  # Default: all checks enabled
        
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
            QGroupBox {
                border: 1px solid #dcdde1;
                border-radius: 4px;
                margin-top: 10px;
                font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
            }
            QCheckBox {
                font-size: 14px;
                padding: 5px;
            }
            QComboBox {
                background-color: #ffffff;
                border: 2px solid #dcdde1;
                border-radius: 4px;
                padding: 8px;
                font-size: 14px;
                min-width: 200px;
            }
            QComboBox:hover {
                border-color: #487eb0;
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

        # Check Types Selection
        check_group = QGroupBox("Select Scan Types")
        check_layout = QHBoxLayout()
        self.check_ast = QCheckBox("AST Analysis")
        self.check_ast.setChecked(True)
        self.check_ast.setToolTip("Analyze code structure using Abstract Syntax Tree (e.g., eval, exec usage)")
        self.check_regex = QCheckBox("Regex Patterns")
        self.check_regex.setChecked(True)
        self.check_regex.setToolTip("Search for suspicious patterns using regular expressions (e.g., hardcoded credentials)")
        self.check_yara = QCheckBox("YARA Rules")
        self.check_yara.setChecked(True)
        self.check_yara.setToolTip("Apply YARA rules for custom malicious code detection")
        self.check_bandit = QCheckBox("Bandit Checks")
        self.check_bandit.setChecked(True)
        self.check_bandit.setToolTip("Perform Bandit-style vulnerability checks (e.g., insecure SSL, subprocess issues)")
        self.check_heuristics = QCheckBox("Heuristic Analysis")
        self.check_heuristics.setChecked(True)
        self.check_heuristics.setToolTip("Apply heuristic checks (e.g., ML suspicion, API keys, hardware access)")
        check_layout.addWidget(self.check_ast)
        check_layout.addWidget(self.check_regex)
        check_layout.addWidget(self.check_yara)
        check_layout.addWidget(self.check_bandit)
        check_layout.addWidget(self.check_heuristics)
        check_layout.addStretch()
        check_group.setLayout(check_layout)
        layout.addWidget(check_group)

        # Control Buttons and Report Mode
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        self.export_btn.setEnabled(False)
        self.report_mode_combo = QComboBox()
        self.report_mode_combo.addItems(["Overall Report", "Separate Reports by Check Type"])
        self.report_mode_combo.setToolTip("Choose whether to generate a single report or separate reports for each check type")
        self.search_vulnerabilities_btn = QPushButton("Vulnerability Search")
        self.search_vulnerabilities_btn.clicked.connect(self.search_vulnerabilities)
        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.report_mode_combo)
        btn_layout.addWidget(self.search_vulnerabilities_btn)
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

    def get_selected_check_types(self):
        check_types = []
        if self.check_ast.isChecked():
            check_types.append("ast")
        if self.check_regex.isChecked():
            check_types.append("regex")
        if self.check_yara.isChecked():
            check_types.append("yara")
        if self.check_bandit.isChecked():
            check_types.append("bandit")
        if self.check_heuristics.isChecked():
            check_types.append("heuristics")
        return check_types

    def start_scan(self):
        repo_url = self.repo_input.text().strip()
        if not repo_url:
            QMessageBox.warning(self, "Error", "Please enter a repository URL")
            return

        self.check_types = self.get_selected_check_types()
        if not self.check_types:
            QMessageBox.warning(self, "Error", "Please select at least one scan type")
            return

        self.log_message(f"Starting scan for repository: {repo_url} with checks: {', '.join(self.check_types)}")
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.progress.setValue(0)

        yara_rules = self.config.get("yara_rules", "")
        self.scanner_thread = ScannerThread(
            repo_url,
            self.token_input.text().strip() or None,
            yara_rules,
            self.check_types
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
            item.url = f"{self.repo_input.text().strip()}/blob/main/{filename}"
            if score >= 70:
                item.setBackground(1, QColor("#ff7675"))
            elif score >= 40:
                item.setBackground(1, QColor("#fdcb6e"))
            else:
                item.setBackground(1, QColor("#55efc4"))
            self.tree.addTopLevelItem(item)

        self.update_details()
        self.update_statistics()

    def update_details(self):
        self.details_text.clear()
        self.details_text.append(f"Performed Checks: {', '.join(self.check_types)}\n{'='*40}\n")
        for filename, data in self.results.items():
            self.details_text.append(f"File: {filename}\n{'-'*40}")
            for key, value in data.items():
                if key == "_code":
                    continue
                if key == "detailed_lines":
                    self.details_text.append(f"{key}:")
                    for line in value:
                        self.details_text.append(f"  {line}")
                elif isinstance(value, dict):
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
        Check Types Used: {', '.join(self.check_types)}
        """
        self.stats_text.setPlainText(stats)

    def export_report(self):
        if not self.results or not self.scores:
            QMessageBox.warning(self, "Error", "No data to export")
            return
        
        report_mode = "overall" if self.report_mode_combo.currentText() == "Overall Report" else "separate"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "",
            "Excel Files (*.xlsx);;All Files (*)")
        
        if path:
            try:
                generate_detailed_report(self.results, self.scores, path, self.check_types, report_mode)
                self.log_message(f"Report exported to {path}")
                if report_mode == "separate":
                    self.log_message("Generated separate reports for each check type")
                QMessageBox.information(self, "Success", "Report generated successfully")
            except Exception as e:
                self.log_message(f"Export error: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    def save_session(self):
        session = {
            "repo_url": self.repo_input.text(),
            "token": self.token_input.text(),
            "results": self.results,
            "scores": self.scores,
            "check_types": self.check_types,
            "report_mode": self.report_mode_combo.currentText()
        }
        save_last_scan(session)

    def load_last_session(self):
        session = load_last_scan()
        if session:
            self.repo_input.setText(session.get("repo_url", ""))
            self.token_input.setText(session.get("token", ""))
            self.results = session.get("results")
            self.scores = session.get("scores")
            self.check_types = session.get("check_types", ["ast", "regex", "yara", "bandit", "heuristics"])
            report_mode = session.get("report_mode", "Overall Report")
            self.report_mode_combo.setCurrentText(report_mode)
            self.check_ast.setChecked("ast" in self.check_types)
            self.check_regex.setChecked("regex" in self.check_types)
            self.check_yara.setChecked("yara" in self.check_types)
            self.check_bandit.setChecked("bandit" in self.check_types)
            self.check_heuristics.setChecked("heuristics" in self.check_types)
            if self.results and self.scores:
                self.display_results()
                self.log_message("Previous session loaded")

    def handle_error(self, message):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setValue(0)
        self.log_message(f"Error: {message}")
        QMessageBox.critical(self, "Error", message)

    def search_vulnerabilities(self):
        QMessageBox.information(self, "Info", "Vulnerability search not implemented yet")

if __name__ == "__main__":
    app = QApplication([])
    window = CodeScannerGUI()
    window.show()
    app.exec_()