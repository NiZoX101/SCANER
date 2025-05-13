import sys
import os
import re
import logging
from datetime import datetime
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QCheckBox, QRadioButton, QTabWidget, QTextEdit,
    QComboBox, QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox, QGroupBox,
    QProgressBar, QLabel, QScrollArea
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QBrush, QColor
from scanner_core import perform_scan, analyze_code, score_maliciousness
from report_generator import generate_detailed_report
from utils import save_last_scan, load_last_scan
from github_utils import get_repository_files

class ScanWorker(QThread):
    progress = pyqtSignal(int, str)  # Progress percentage, filename
    result = pyqtSignal(dict, dict, list)  # Results, scores, files
    error = pyqtSignal(str)  # Error message
    log = pyqtSignal(str)  # Log message

    def __init__(self, repo_url, token, yara_source, check_types):
        super().__init__()
        self.repo_url = repo_url
        self.token = token
        self.yara_source = yara_source
        self.check_types = check_types

    def run(self):
        try:
            files = get_repository_files(self.repo_url, self.token)
            if not files:
                self.error.emit("No Python files found in repository.")
                return

            total_files = len(files)
            results = {}
            scores = {}
            for i, (filename, code) in enumerate(files):
                self.log.emit(f"Analyzing {filename}")
                partial_results = analyze_code([(filename, code)], self.yara_source, self.check_types)
                results.update(partial_results)
                partial_scores = score_maliciousness(partial_results)
                scores.update(partial_scores)
                progress = int((i + 1) / total_files * 100)
                self.progress.emit(progress, filename)
                self.msleep(10)  # Small delay to ensure UI updates

            self.result.emit(results, scores, files)
        except Exception as e:
            self.error.emit(str(e))

class QtLogHandler(logging.Handler):
    def __init__(self, text_edit):
        super().__init__()
        self.text_edit = text_edit

    def emit(self, record):
        msg = self.format(record)
        self.text_edit.append(msg)
        QApplication.processEvents()

class CodeScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Code Security Scanner")
        self.setGeometry(100, 100, 1200, 800)

        # Central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Tab widget
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)

        # Scan Tab
        self.scan_tab = QWidget()
        self.tabs.addTab(self.scan_tab, "Scan")
        self.setup_scan_tab()

        # Results Tab
        self.results_tab = QWidget()
        self.tabs.addTab(self.results_tab, "Results")
        self.setup_results_tab()

        # Details Tab
        self.details_tab = QWidget()
        self.tabs.addTab(self.details_tab, "Details")
        self.setup_details_tab()

        # Logs Tab
        self.logs_tab = QWidget()
        self.tabs.addTab(self.logs_tab, "Logs")
        self.setup_logs_tab()

        # Chart Tab
        self.chart_tab = QWidget()
        self.tabs.addTab(self.chart_tab, "Charts")
        self.setup_chart_tab()

        # Interaction Graph Tab
        self.graph_tab = QWidget()
        self.tabs.addTab(self.graph_tab, "Interaction Graph")
        self.setup_graph_tab()

        # Setup logging
        self.logger = logging.getLogger("CodeScanner")
        self.logger.setLevel(logging.INFO)
        handler = QtLogHandler(self.logs_text)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(handler)

        # Load last scan
        self.last_scan = load_last_scan()
        if self.last_scan:
            self.populate_last_scan()

        # Apply stylesheet
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #2b2b2b; color: #ffffff; }
            QLineEdit, QTextEdit, QComboBox, QTableWidget {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 5px;
            }
            QLineEdit:focus, QComboBox:focus { border: 1px solid #1e90ff; }
            QPushButton {
                background-color: #1e90ff;
                color: #ffffff;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #4682b4; }
            QPushButton:pressed { background-color: #1c86ee; }
            QCheckBox, QRadioButton { color: #ffffff; }
            QTabWidget::pane { border: 1px solid #555555; }
            QTabBar::tab {
                background: #3c3f41;
                color: #ffffff;
                padding: 8px 15px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #1e90ff;
                color: #ffffff;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 4px;
                margin-top: 10px;
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
                color: #ffffff;
            }
            QTableWidget::item { padding: 5px; }
            QHeaderView::section {
                background-color: #3c3f41;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555555;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 4px;
                text-align: center;
                background-color: #3c3f41;
            }
            QProgressBar::chunk {
                background-color: #1e90ff;
                border-radius: 2px;
            }
            QLabel { color: #ffffff; }
            QScrollArea { background-color: #2b2b2b; border: none; }
        """)

    def setup_scan_tab(self):
        layout = QVBoxLayout(self.scan_tab)

        # Input Group
        input_group = QGroupBox("Scan Configuration")
        input_layout = QFormLayout()
        input_group.setLayout(input_layout)

        # Repository URL
        self.repo_url_input = QLineEdit()
        input_layout.addRow("Repository URL:", self.repo_url_input)

        # GitHub Token
        self.token_input = QLineEdit()
        self.token_input.setEchoMode(QLineEdit.Password)
        input_layout.addRow("GitHub Token:", self.token_input)

        # YARA Rules File
        yara_layout = QHBoxLayout()
        self.yara_input = QLineEdit()
        yara_browse = QPushButton("Browse")
        yara_browse.clicked.connect(self.browse_yara)
        yara_layout.addWidget(self.yara_input)
        yara_layout.addWidget(yara_browse)
        input_layout.addRow("YARA Rules File:", yara_layout)

        # Output File
        output_layout = QHBoxLayout()
        self.output_input = QLineEdit("scan_report.xlsx")
        output_browse = QPushButton("Browse")
        output_browse.clicked.connect(self.browse_output)
        output_layout.addWidget(self.output_input)
        output_layout.addWidget(output_browse)
        input_layout.addRow("Output Report:", output_layout)

        layout.addWidget(input_group)

        # Check Types Group
        check_group = QGroupBox("Check Types")
        check_layout = QHBoxLayout()
        self.check_types = {
            "ast": QCheckBox("AST"),
            "regex": QCheckBox("Regex"),
            "yara": QCheckBox("YARA"),
            "bandit": QCheckBox("Bandit"),
            "heuristics": QCheckBox("Heuristics")
        }
        for checkbox in self.check_types.values():
            checkbox.setChecked(True)
            check_layout.addWidget(checkbox)
        check_group.setLayout(check_layout)
        layout.addWidget(check_group)

        # Report Mode Group
        mode_group = QGroupBox("Report Mode")
        mode_layout = QHBoxLayout()
        self.overall_mode = QRadioButton("Overall")
        self.separate_mode = QRadioButton("Separate")
        self.overall_mode.setChecked(True)
        mode_layout.addWidget(self.overall_mode)
        mode_layout.addWidget(self.separate_mode)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)

        # Progress Bar
        self.progress_label = QLabel("Scan Progress:")
        layout.addWidget(self.progress_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Scan Button
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button, alignment=Qt.AlignCenter)
        layout.addStretch()

    def setup_results_tab(self):
        layout = QVBoxLayout(self.results_tab)

        # Summary
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMaximumHeight(150)
        layout.addWidget(self.summary_text)

        # Results Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["File", "Risk Score"])
        self.results_table.setSelectionMode(QTableWidget.SingleSelection)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setColumnWidth(0, 600)
        layout.addWidget(self.results_table)

    def setup_details_tab(self):
        layout = QVBoxLayout(self.details_tab)

        # File Selection
        file_layout = QHBoxLayout()
        file_label = QLabel("Select File:")
        self.file_combo = QComboBox()
        self.file_combo.currentIndexChanged.connect(self.update_details)
        file_layout.addWidget(file_label)
        file_layout.addWidget(self.file_combo)
        layout.addLayout(file_layout)

        # Details Table
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(5)
        self.details_table.setHorizontalHeaderLabels(["Line", "Type", "Code Snippet", "Reason", "Advice"])
        self.details_table.setSelectionMode(QTableWidget.NoSelection)
        self.details_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.details_table.horizontalHeader().setStretchLastSection(True)
        self.details_table.setColumnWidth(0, 80)
        self.details_table.setColumnWidth(1, 100)
        self.details_table.setColumnWidth(2, 200)
        self.details_table.setColumnWidth(3, 250)
        self.details_table.setColumnWidth(4, 250)
        layout.addWidget(self.details_table)

    def setup_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        layout.addWidget(self.logs_text)

    def setup_chart_tab(self):
        layout = QVBoxLayout(self.chart_tab)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Findings by File and Check Type Chart
        self.findings_chart_label = QLabel("Findings by File and Check Type")
        scroll_layout.addWidget(self.findings_chart_label)
        self.findings_chart_image = QLabel()
        self.findings_chart_image.setAlignment(Qt.AlignCenter)
        scroll_layout.addWidget(self.findings_chart_image)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

    def setup_graph_tab(self):
        layout = QVBoxLayout(self.graph_tab)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Interaction Graph
        self.graph_label = QLabel("File Interaction Graph")
        scroll_layout.addWidget(self.graph_label)
        self.graph_image = QLabel()
        self.graph_image.setAlignment(Qt.AlignCenter)
        scroll_layout.addWidget(self.graph_image)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

    def browse_yara(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select YARA Rules File", "", "YARA Files (*.yar *.yara);;All Files (*.*)")
        if filename:
            self.yara_input.setText(filename)

    def browse_output(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Select Output File", "scan_report.xlsx", "Excel Files (*.xlsx);;All Files (*.*)")
        if filename:
            self.output_input.setText(filename)

    def start_scan(self):
        repo_url = self.repo_url_input.text()
        token = self.token_input.text()
        yara_file = self.yara_input.text()
        output_path = self.output_input.text()
        selected_checks = [check for check, cb in self.check_types.items() if cb.isChecked()]
        report_mode = "overall" if self.overall_mode.isChecked() else "separate"

        if not repo_url or not token or not output_path:
            QMessageBox.critical(self, "Error", "Please fill in all required fields.")
            return

        if not selected_checks:
            QMessageBox.critical(self, "Error", "Please select at least one check type.")
            return

        yara_source = None
        if yara_file and os.path.exists(yara_file):
            with open(yara_file, "r") as f:
                yara_source = f.read()

        self.progress_bar.setValue(0)
        self.logger.info("Starting scan...")
        self.results_table.setRowCount(0)
        self.details_table.setRowCount(0)
        self.file_combo.clear()
        self.summary_text.clear()
        self.findings_chart_image.clear()
        self.graph_image.clear()
        self.scan_button.setEnabled(False)

        # Start worker thread
        self.worker = ScanWorker(repo_url, token, yara_source, selected_checks)
        self.worker.progress.connect(self.update_progress)
        self.worker.result.connect(lambda r, s, f: self.scan_completed(r, s, f, output_path, selected_checks, report_mode))
        self.worker.error.connect(self.scan_failed)
        self.worker.log.connect(self.logger.info)
        self.worker.start()

    def update_progress(self, value, filename):
        self.progress_bar.setValue(value)
        self.logger.info(f"Progress: {value}% ({filename})")

    def generate_charts(self, scores, results, selected_checks):
        # Initialize data for grouped bar chart
        files = list(results.keys())
        check_types = ['AST', 'Regex', 'YARA', 'Bandit', 'Heuristics']
        check_types = [ct for ct in check_types if ct.lower() in selected_checks or (ct == 'Heuristics' and 'heuristics' in selected_checks)]
        
        # Count findings per file and check type
        findings_data = {file: {ct: 0 for ct in check_types} for file in files}
        for file, patterns in results.items():
            for finding in patterns.get('detailed_findings', []):
                match = re.match(r"Line (\d+|-): (.*?) \[Type: (.*?)\] \[Reason: (.*?)\] \[Advice: (.*?)\]", finding)
                if match:
                    check_type = match.group(3)
                    if check_type in findings_data[file]:
                        findings_data[file][check_type] += 1
            if 'heuristics' in selected_checks:
                for finding in patterns.get('detailed_lines', []):
                    findings_data[file]['Heuristics'] += 1

        # Prepare data for plotting
        x = np.arange(len(files))  # File indices
        width = 0.15  # Width of each bar
        colors = ['#1e90ff', '#ffa500', '#32c832', '#dc3232', '#800080']  # Colors for AST, Regex, YARA, Bandit, Heuristics
        
        # Create grouped bar chart
        plt.figure(figsize=(12, 8))
        plt.style.use('dark_background')
        
        for i, check_type in enumerate(check_types):
            counts = [findings_data[file][check_type] for file in files]
            bars = plt.bar(x + i * width, counts, width, label=check_type, color=colors[i % len(colors)])
            
            # Add value labels on top of bars
            for bar in bars:
                height = bar.get_height()
                if height > 0:  # Only label non-zero bars for clarity
                    plt.text(bar.get_x() + bar.get_width()/2., height, f'{int(height)}',
                            ha='center', va='bottom', fontsize=8, color='#ffffff')

        plt.xlabel('Files', fontsize=12, color='#ffffff')
        plt.ylabel('Number of Findings', fontsize=12, color='#ffffff')
        plt.title('Findings by File and Check Type', fontsize=16, color='#ffffff')
        plt.xticks(x + width * (len(check_types) - 1) / 2, files, rotation=45, ha='right', color='#ffffff')
        plt.yticks(color='#ffffff')
        plt.legend(fontsize=10, loc='upper right', frameon=True, facecolor='#3c3f41', edgecolor='#ffffff')
        plt.grid(True, axis='y', linestyle='--', alpha=0.7, color='#555555')
        plt.tight_layout()
        
        plt.savefig('findings_by_check.png', facecolor='#2b2b2b', edgecolor='#2b2b2b')
        plt.close()

        # Load image into GUI
        findings_pixmap = QPixmap('findings_by_check.png')
        self.findings_chart_image.setPixmap(findings_pixmap.scaled(1200, 800, Qt.KeepAspectRatio))

    def generate_interaction_graph(self, results, files):
        G = nx.DiGraph()
        file_names = [f[0] for f in files]

        # Add nodes (files)
        for fname in file_names:
            G.add_node(fname)

        # Add edges based on imports
        import_pattern = r"^(?:from\s+(\w+)\s+)?import\s+([\w, ]+)"
        for fname, patterns in results.items():
            code = patterns.get('_code', '')
            for line in code.splitlines():
                match = re.match(import_pattern, line.strip())
                if match:
                    imported_modules = [m.strip() for m in match.group(2).split(',')]
                    for mod in imported_modules:
                        # Check if the imported module corresponds to another file in the repo
                        for other_fname in file_names:
                            if other_fname != fname and mod.lower() in other_fname.lower():
                                G.add_edge(fname, other_fname)

        # If graph is empty, create a simple graph based on shared patterns
        if not G.edges():
            for fname1 in file_names:
                for fname2 in file_names:
                    if fname1 < fname2:
                        patterns1 = results.get(fname1, {})
                        patterns2 = results.get(fname2, {})
                        shared = set(k for k, v in patterns1.items() if v and k not in ['_code', 'detailed_findings', 'detailed_lines']) & \
                                 set(k for k, v in patterns2.items() if v and k not in ['_code', 'detailed_findings', 'detailed_lines'])
                        if shared:
                            G.add_edge(fname1, fname2, weight=len(shared))

        # Draw graph
        plt.figure(figsize=(10, 8))
        plt.style.use('dark_background')
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        nx.draw(G, pos, with_labels=True, node_color='#1e90ff', node_size=1500, font_size=8, 
                font_color='white', edge_color='#555555', arrows=True)
        plt.title('File Interaction Graph (Imports and Shared Patterns)', fontsize=16, color='#ffffff')
        plt.tight_layout()
        plt.savefig('interaction_graph.png', facecolor='#2b2b2b', edgecolor='#2b2b2b')
        plt.close()

        # Load image into GUI
        graph_pixmap = QPixmap('interaction_graph.png')
        self.graph_image.setPixmap(graph_pixmap.scaled(1000, 800, Qt.KeepAspectRatio))

    def scan_completed(self, results, scores, files, output_path, selected_checks, report_mode):
        try:
            generate_detailed_report(results, scores, output_path, selected_checks, report_mode)

            # Save scan session
            session = {
                "repo_url": self.repo_url_input.text(),
                "token": self.token_input.text(),
                "yara_file": self.yara_input.text(),
                "output_path": output_path,
                "check_types": selected_checks,
                "report_mode": report_mode,
                "results": results,
                "scores": scores,
                "files": [f[0] for f in files],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            save_last_scan(session)
            self.last_scan = session

            # Update Summary
            self.summary_text.append(f"Scan completed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.summary_text.append(f"Total Files Scanned: {len(scores)}")
            avg_score = sum(scores.values()) / len(scores) if scores else 0
            self.summary_text.append(f"Average Risk Score: {avg_score:.2f}")
            high_risk = sum(1 for s in scores.values() if s >= 70)
            self.summary_text.append(f"High Risk Files (Score >= 70): {high_risk}\n")
            self.summary_text.append(f"Check Types Used: {', '.join(selected_checks)}")

            # Update Results Table with Color Indication
            self.results_table.setRowCount(len(scores))
            for row, (filename, score) in enumerate(scores.items()):
                self.results_table.setItem(row, 0, QTableWidgetItem(filename))
                score_item = QTableWidgetItem(f"{score}")
                if score >= 70:
                    score_item.setBackground(QBrush(QColor(220, 50, 50)))  # Red
                elif score >= 40:
                    score_item.setBackground(QBrush(QColor(255, 165, 0)))  # Orange
                else:
                    score_item.setBackground(QBrush(QColor(50, 200, 50)))  # Green
                self.results_table.setItem(row, 1, score_item)

            # Update Details Tab
            self.file_combo.addItems(scores.keys())
            if scores:
                self.update_details()

            # Generate Charts and Graph
            self.generate_charts(scores, results, selected_checks)
            self.generate_interaction_graph(results, files)

            self.logger.info("Scan completed successfully")
            QMessageBox.information(self, "Success", "Scan completed successfully!")
        except Exception as e:
            self.logger.error(f"Post-scan processing failed: {str(e)}")
            QMessageBox.critical(self, "Error", f"Post-scan processing failed: {str(e)}")
        finally:
            self.scan_button.setEnabled(True)
            self.progress_bar.setValue(100)

    def scan_failed(self, error_msg):
        self.logger.error(f"Scan failed: {error_msg}")
        QMessageBox.critical(self, "Error", f"Scan failed: {error_msg}")
        self.scan_button.setEnabled(True)
        self.progress_bar.setValue(0)

    def populate_last_scan(self):
        if not self.last_scan:
            return
        self.repo_url_input.setText(self.last_scan.get("repo_url", ""))
        self.token_input.setText(self.last_scan.get("token", ""))
        self.yara_input.setText(self.last_scan.get("yara_file", ""))
        self.output_input.setText(self.last_scan.get("output_path", "scan_report.xlsx"))
        for check, cb in self.check_types.items():
            cb.setChecked(check in self.last_scan.get("check_types", []))
        if self.last_scan.get("report_mode", "overall") == "overall":
            self.overall_mode.setChecked(True)
        else:
            self.separate_mode.setChecked(True)

        # Populate summary
        scores = self.last_scan.get("scores", {})
        self.summary_text.clear()
        self.summary_text.append(f"Last Scan: {self.last_scan.get('timestamp', 'Unknown')}\n")
        self.summary_text.append(f"Total Files Scanned: {len(scores)}")
        avg_score = sum(scores.values()) / len(scores) if scores else 0
        self.summary_text.append(f"Average Risk Score: {avg_score:.2f}")
        high_risk = sum(1 for s in scores.values() if s >= 70)
        self.summary_text.append(f"High Risk Files (Score >= 70): {high_risk}\n")
        self.summary_text.append(f"Check Types Used: {', '.join(self.last_scan.get('check_types', []))}")

        # Populate results table
        self.results_table.setRowCount(len(scores))
        for row, (filename, score) in enumerate(scores.items()):
            self.results_table.setItem(row, 0, QTableWidgetItem(filename))
            score_item = QTableWidgetItem(f"{score}")
            if score >= 70:
                score_item.setBackground(QBrush(QColor(220, 50, 50)))
            elif score >= 40:
                score_item.setBackground(QBrush(QColor(255, 165, 0)))
            else:
                score_item.setBackground(QBrush(QColor(50, 200, 50)))
            self.results_table.setItem(row, 1, score_item)

        # Populate details
        self.file_combo.clear()
        self.file_combo.addItems(scores.keys())
        if scores:
            self.update_details()

        # Populate charts and graph
        self.generate_charts(scores, self.last_scan.get("results", {}), self.last_scan.get("check_types", []))
        self.generate_interaction_graph(self.last_scan.get("results", {}), [(f, '') for f in self.last_scan.get("files", [])])

    def update_details(self):
        self.details_table.setRowCount(0)
        filename = self.file_combo.currentText()
        if not filename or not self.last_scan:
            return

        results = self.last_scan.get("results", {})
        patterns = results.get(filename, {})
        selected_checks = self.last_scan.get("check_types", [])
        findings = []

        # Scanner Core Findings (filtered by selected check types)
        for finding in patterns.get("detailed_findings", []):
            match = re.match(r"Line (\d+|-): (.*?) \[Type: (.*?)\] \[Reason: (.*?)\] \[Advice: (.*?)\]", finding)
            if match:
                line_num, snippet, check_type, reason, advice = match.groups()
                check_mapping = {
                    "AST": "ast",
                    "Regex": "regex",
                    "YARA": "yara",
                    "Bandit": "bandit"
                }
                check_key = check_mapping.get(check_type)
                if check_key in selected_checks:
                    findings.append((line_num, check_type, snippet, reason, advice))

        # Heuristics Findings (only if heuristics is selected)
        if "heuristics" in selected_checks:
            for finding in patterns.get("detailed_lines", []):
                match = re.match(r"Line (\d+): (.*?) \[Причина: (.*?)\] \[Совет: (.*?)\]", finding)
                if match:
                    line_num, snippet, reason, advice = match.groups()
                    findings.append((line_num, "Heuristics", snippet, reason, advice))

        # Populate table
        self.details_table.setRowCount(len(findings))
        for row, (line_num, check_type, snippet, reason, advice) in enumerate(findings):
            self.details_table.setItem(row, 0, QTableWidgetItem(line_num))
            self.details_table.setItem(row, 1, QTableWidgetItem(check_type))
            self.details_table.setItem(row, 2, QTableWidgetItem(snippet))
            self.details_table.setItem(row, 3, QTableWidgetItem(reason))
            self.details_table.setItem(row, 4, QTableWidgetItem(advice))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CodeScannerGUI()
    window.show()
    sys.exit(app.exec_())