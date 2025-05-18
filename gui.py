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
import requests
import json
from io import BytesIO
import base64

# Stub implementations for missing modules
def save_last_scan(session):
    try:
        with open('last_scan.json', 'w', encoding='utf-8') as f:
            json.dump(session, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Не удалось сохранить последний скан: {e}")

def load_last_scan():
    try:
        with open('last_scan.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def get_repository_files(repo_url, token):
    from github_utils import get_repository_files
    return get_repository_files(repo_url, token)

class ScanWorker(QThread):
    progress = pyqtSignal(int, str)
    result = pyqtSignal(dict, dict, list)
    error = pyqtSignal(str)
    log = pyqtSignal(str)

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
                self.error.emit("Не найдено файлов Python в репозитории.")
                return

            total_files = len(files)
            results = {}
            scores = {}
            
            for i, (filename, code) in enumerate(files):
                self.log.emit(f"Анализ файла {filename}")
                
                # Выполняем только выбранные типы проверок
                partial_results = analyze_code([(filename, code)], self.yara_source, self.check_types)
                results.update(partial_results)
                
                # Вычисляем баллы
                partial_scores = score_maliciousness(partial_results, self.check_types)
                scores.update(partial_scores)
                
                progress = int((i + 1) / total_files * 100)
                self.progress.emit(progress, filename)
                self.msleep(10)

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
        self.setWindowTitle("Расширенный сканер безопасности кода")
        self.setGeometry(100, 100, 1200, 800)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)

        self.scan_tab = QWidget()
        self.tabs.addTab(self.scan_tab, "Скан")
        self.setup_scan_tab()

        self.results_tab = QWidget()
        self.tabs.addTab(self.results_tab, "Результаты")
        self.setup_results_tab()

        self.details_tab = QWidget()
        self.tabs.addTab(self.details_tab, "Подробности")
        self.setup_details_tab()

        self.logs_tab = QWidget()
        self.tabs.addTab(self.logs_tab, "Логи")
        self.setup_logs_tab()

        self.chart_tab = QWidget()
        self.tabs.addTab(self.chart_tab, "Диаграммы")
        self.setup_chart_tab()

        self.graph_tab = QWidget()
        self.tabs.addTab(self.graph_tab, "График взаимодействия")
        self.setup_graph_tab()

        self.logger = logging.getLogger("CodeScanner")
        self.logger.setLevel(logging.INFO)
        handler = QtLogHandler(self.logs_text)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(handler)

        self.last_scan = load_last_scan()
        if self.last_scan:
            self.populate_last_scan()

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

        input_group = QGroupBox("Конфигурация сканирования")
        input_layout = QFormLayout()
        input_group.setLayout(input_layout)

        self.repo_url_input = QLineEdit()
        input_layout.addRow("URL репозитория:", self.repo_url_input)

        self.token_input = QLineEdit()
        self.token_input.setEchoMode(QLineEdit.Password)
        input_layout.addRow("Токен GitHub:", self.token_input)

        self.io_net_api_key_input = QLineEdit()
        self.io_net_api_key_input.setEchoMode(QLineEdit.Password)
        self.io_net_api_key_input.setPlaceholderText("Введите ключ API io.net или установите переменную окружения IO_NET_API_KEY")
        input_layout.addRow("Ключ API io.net (опционально):", self.io_net_api_key_input)

        yara_layout = QHBoxLayout()
        self.yara_input = QLineEdit()
        yara_browse = QPushButton("Обзор")
        yara_browse.clicked.connect(self.browse_yara)
        yara_layout.addWidget(self.yara_input)
        yara_layout.addWidget(yara_browse)
        input_layout.addRow("Файл правил YARA:", yara_layout)

        output_layout = QHBoxLayout()
        self.output_input = QLineEdit("scan_report.xlsx")
        output_browse = QPushButton("Обзор")
        output_browse.clicked.connect(self.browse_output)
        output_layout.addWidget(self.output_input)
        output_layout.addWidget(output_browse)
        input_layout.addRow("Путь к отчету:", output_layout)

        layout.addWidget(input_group)

        check_group = QGroupBox("Типы проверок")
        check_layout = QHBoxLayout()
        self.check_types = {
            "ast": QCheckBox("AST"),
            "regex": QCheckBox("Регулярные выражения"),
            "yara": QCheckBox("YARA"),
            "heuristics": QCheckBox("Эвристика")
        }
        display_names = {
            "ast": "AST",
            "regex": "Регулярные выражения",
            "yara": "YARA",
            "heuristics": "Эвристика"
        }
        for check, checkbox in self.check_types.items():
            checkbox.setText(display_names[check])
            checkbox.setChecked(True)
            check_layout.addWidget(checkbox)
        check_group.setLayout(check_layout)
        layout.addWidget(check_group)

        mode_group = QGroupBox("Режим отчета")
        mode_layout = QHBoxLayout()
        self.overall_mode = QRadioButton("Общий")
        self.separate_mode = QRadioButton("Отдельный")
        self.overall_mode.setChecked(True)
        mode_layout.addWidget(self.overall_mode)
        mode_layout.addWidget(self.separate_mode)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)

        self.progress_label = QLabel("Прогресс сканирования:")
        layout.addWidget(self.progress_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Начать скан")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)

        self.io_net_button = QPushButton("Резюме с помощью AI")
        self.io_net_button.clicked.connect(self.summarize_with_io_net)
        self.io_net_button.setEnabled(False)
        button_layout.addWidget(self.io_net_button)

        layout.addLayout(button_layout)
        layout.addStretch()

    def setup_results_tab(self):
        layout = QVBoxLayout(self.results_tab)
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMinimumHeight(300)
        layout.addWidget(self.summary_text)
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["Файл", "Балл риска"])
        self.results_table.setSelectionMode(QTableWidget.SingleSelection)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setColumnWidth(0, 600)
        layout.addWidget(self.results_table)

    def setup_details_tab(self):
        layout = QVBoxLayout(self.details_tab)
        file_layout = QHBoxLayout()
        file_label = QLabel("Выберите файл:")
        self.file_combo = QComboBox()
        self.file_combo.currentIndexChanged.connect(self.update_details)
        file_layout.addWidget(file_label)
        file_layout.addWidget(self.file_combo)
        layout.addLayout(file_layout)
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(5)
        self.details_table.setHorizontalHeaderLabels(["Номер строки", "Тип", "Фрагмент кода", "Причина", "Совет"])
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
        self.findings_chart_label = QLabel("Нахождения по файлам и типам проверок")
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
        self.graph_label = QLabel("График взаимодействия файлов")
        scroll_layout.addWidget(self.graph_label)
        self.graph_image = QLabel()
        self.graph_image.setAlignment(Qt.AlignCenter)
        scroll_layout.addWidget(self.graph_image)
        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

    def browse_yara(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Выберите файл правил YARA", "", "YARA Files (*.yar *.yara);;Все файлы (*.*)")
        if filename:
            self.yara_input.setText(filename)

    def browse_output(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Выберите путь для отчета", "scan_report.xlsx", "Excel Files (*.xlsx);;Все файлы (*.*)")
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
            QMessageBox.critical(self, "Ошибка", "Пожалуйста, заполните все обязательные поля.")
            return

        if not selected_checks:
            QMessageBox.critical(self, "Ошибка", "Пожалуйста, выберите хотя бы один тип проверки.")
            return

        yara_source = None
        if yara_file and os.path.exists(yara_file):
            with open(yara_file, "r") as f:
                yara_source = f.read()

        self.progress_bar.setValue(0)
        self.logger.info("Начало сканирования...")
        self.results_table.setRowCount(0)
        self.details_table.setRowCount(0)
        self.file_combo.clear()
        self.summary_text.clear()
        self.findings_chart_image.clear()
        self.graph_image.clear()
        self.scan_button.setEnabled(False)
        self.io_net_button.setEnabled(False)

        self.worker = ScanWorker(repo_url, token, yara_source, selected_checks)
        self.worker.progress.connect(self.update_progress)
        self.worker.result.connect(lambda r, s, f: self.scan_completed(r, s, f, output_path, selected_checks, report_mode))
        self.worker.error.connect(self.scan_failed)
        self.worker.log.connect(self.logger.info)
        self.worker.start()

    def update_progress(self, value, filename):
        self.progress_bar.setValue(value)
        self.logger.info(f"Прогресс: {value}% ({filename})")

    def generate_charts(self, scores, results, selected_checks):
        if not results or not scores:
            self.findings_chart_image.clear()
            return
        files = list(results.keys())
        check_types = ['ast', 'regex', 'yara', 'heuristics']
        check_types = [ct for ct in check_types if ct in selected_checks]
    
        # Инициализация данных для диаграммы
        findings_data = {file: {ct: 0 for ct in check_types} for file in files}
    
        for file, patterns in results.items():
            # Подсчёт находок для каждого типа проверки
            for finding in patterns.get('detailed_findings', []):
                # Парсим тип проверки из строки находки
                match = re.search(r"\[Type:\s*(\w+)\]", finding)
                if match:
                    check_type = match.group(1).lower()
                    if check_type in findings_data[file]:
                        findings_data[file][check_type] += 1
        
            # Эвристические проверки могут быть в detailed_lines
            if 'heuristics' in selected_checks:
                findings_data[file]['heuristics'] += len([line for line in patterns.get('detailed_lines', []) if re.search(r"\[Type: Heuristics\]", line)])
    
        # Построение диаграммы
        x = np.arange(len(files))
        width = 0.15
        colors = ['#1e90ff', '#ffa500', '#32c832', '#800080']
    
        plt.figure(figsize=(15, 10))  # Увеличен размер фигуры
        plt.style.use('dark_background')
    
        for i, check_type in enumerate(check_types):
            counts = [findings_data[file][check_type] for file in files]
            bars = plt.bar(x + i * width, counts, width, 
                          label=check_type.capitalize(), 
                          color=colors[i % len(colors)])
        
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    plt.text(bar.get_x() + bar.get_width()/2., height, 
                            f'{int(height)}', ha='center', va='bottom', 
                            fontsize=8, color='#ffffff')
    
        plt.xlabel('Файлы', fontsize=12, color='#ffffff')
        plt.ylabel('Количество находок', fontsize=12, color='#ffffff')
        plt.title('Нахождения по файлам и типам проверок', fontsize=16, color='#ffffff')
        plt.xticks(x + width * (len(check_types) - 1) / 2, 
                  [os.path.basename(f) for f in files], 
                  rotation=45, ha='right', color='#ffffff')
        plt.yticks(color='#ffffff')
        plt.legend(fontsize=10, loc='upper right', frameon=True, 
                  facecolor='#3c3f41', edgecolor='#ffffff')
        plt.grid(True, axis='y', linestyle='--', alpha=0.7, color='#555555')
        plt.tight_layout()
    
        # Сохранение и отображение диаграммы
        buffer = BytesIO()
        plt.savefig(buffer, format='png', facecolor='#2b2b2b', edgecolor='#2b2b2b', dpi=150)  # Увеличен dpi
        plt.close()
        buffer.seek(0)
        findings_pixmap = QPixmap()
        findings_pixmap.loadFromData(buffer.read())
        # Динамическое масштабирование с минимальным размером 1200x900
        target_width = max(1200, self.findings_chart_image.width())
        target_height = max(900, self.findings_chart_image.height())
        self.findings_chart_image.setPixmap(findings_pixmap.scaled(
            target_width, target_height, Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))

    def generate_interaction_graph(self, results, files):
        G = nx.DiGraph()
        file_names = [f[0] for f in files]
        for fname in file_names:
            G.add_node(fname)
        import_pattern = r"^(?:from\s+(\w+)\s+)?import\s+([\w, ]+)"
        for fname, patterns in results.items():
            code = patterns.get('_code', '')
            for line in code.splitlines():
                match = re.match(import_pattern, line.strip())
                if match:
                    imported_modules = [m.strip() for m in match.group(2).split(',')]
                    for mod in imported_modules:
                        for other_fname in file_names:
                            if other_fname != fname and mod.lower() in other_fname.lower():
                                G.add_edge(fname, other_fname)
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
        if not G.nodes():
            self.graph_image.clear()
            return
        plt.figure(figsize=(10, 8))
        plt.style.use('dark_background')
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        nx.draw(G, pos, with_labels=True, node_color='#1e90ff', node_size=1500, font_size=8,
                font_color='white', edge_color='#555555', arrows=True)
        plt.title('График взаимодействия файлов (Импорты и общие шаблоны)', fontsize=16, color='#ffffff')
        plt.subplots_adjust(left=0.15, right=0.85, top=0.9, bottom=0.1)
        buffer = BytesIO()
        plt.savefig(buffer, format='png', facecolor='#2b2b2b', edgecolor='#2b2b2b')
        plt.close()
        buffer.seek(0)
        graph_pixmap = QPixmap()
        graph_pixmap.loadFromData(buffer.read())
        self.graph_image.setPixmap(graph_pixmap.scaled(1000, 800, Qt.KeepAspectRatio))

    def summarize_with_io_net(self):
        if not self.last_scan:
            QMessageBox.critical(self, "Ошибка", "Нет результатов сканирования. Пожалуйста, выполните скан сначала.")
            return

        results = self.last_scan.get("results", {})
        scores = self.last_scan.get("scores", {})
        selected_checks = self.last_scan.get("check_types", [])

        api_key = self.io_net_api_key_input.text() or os.environ.get("IO_NET_API_KEY")
        if not api_key:
            QMessageBox.critical(self, "Ошибка", "Требуется ключ API io.net. Установите его в поле ввода или как переменную окружения IO_NET_API_KEY.")
            return

        report_text = "Отчет об анализе безопасности кода\n\n"
        report_text += f"Общее количество отсканированных файлов: {len(scores)}\n"
        report_text += f"Средний балл риска: {sum(scores.values()) / len(scores) if scores else 0:.2f}\n"
        report_text += f"Файлы с высоким риском (балл >= 70): {sum(1 for s in scores.values() if s >= 70)}\n"
        report_text += f"Использованные типы проверок: {', '.join(selected_checks)}\n\n"
        report_text += "Найденные проблемы по файлам:\n"
        for filename, patterns in results.items():
            report_text += f"\nФайл: {filename} (Балл риска: {scores.get(filename, 0)})\n"
            for finding in patterns.get("detailed_findings", []):
                report_text += f"  {finding}\n"
            for finding in patterns.get("detailed_lines", []):
                report_text += f"  {finding}\n"

        system_message = "Система анализа безопасности кода."
        user_message = (
            "На основе предоставленного отчета об анализе безопасности кода, содержащего результаты методов сканирования (AST, Регулярные выражения, YARA, Эвристика), составить официальный отчет на русском языке со следующей структурой:\n"
            "1. Выявленные уязвимости и потенциальные угрозы (перечислить категории уязвимостей с указанием файлов, строк и рисков).\n"
            "2. Общая оценка безопасности (указать уровень риска: Низкий, Средний, Высокий, с обоснованием).\n"
            "3. Рекомендации по устранению уязвимостей (с указанием приоритетов: Приоритет 1 - Высокий, Приоритет 2 - Средний, Приоритет 3 - Низкий).\n"
            "Отчет должен быть представлен в формализованном стиле без разговорных элементов, промежуточных размышлений, комментариев о процессе анализа (например, 'хм', 'давайте посмотрим', 'нужно убедиться', 'проверю') и любых других неформальных вставок. Выводить только финальный структурированный отчет без секции 'think'. Данные для анализа:\n\n"
            f"{report_text}\n\n"
            "Составить отчет."
        )

        try:
            self.logger.info("Отправка отчета в API io.net...")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            data = {
                "model": "deepseek-ai/DeepSeek-R1",
                "messages": [
                    {
                        "role": "system",
                        "content": system_message
                    },
                    {
                        "role": "user",
                        "content": user_message
                    }
                ]
            }
            self.logger.debug(f"Отправляемые данные: {json.dumps(data, indent=2)}")
            response = requests.post(
                "https://api.intelligence.io.solutions/api/v1/chat/completions",
                headers=headers,
                json=data
            )
            response.raise_for_status()
            data = response.json()
            io_net_response = data["choices"][0]["message"]["content"]
            if "</think>" in io_net_response:
                io_net_response = io_net_response.split("</think>\n\n")[1]
            else:
                io_net_response = io_net_response.strip()

            self.summary_text.append("\n=== Отчет анализа безопасности от io.net ===\n")
            self.summary_text.append(io_net_response)
            self.logger.info("Анализ io.net успешно завершен.")
            QMessageBox.information(self, "Успех", "Анализ безопасности от io.net завершен и добавлен во вкладку Результаты.")

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Не удалось выполнить анализ io.net: {str(e)}")
            if hasattr(e.response, 'text'):
                self.logger.error(f"Ответ сервера: {e.response.text}")
            QMessageBox.critical(self, "Ошибка", f"Анализ от io.net не выполнен: {str(e)}")

    def scan_completed(self, results, scores, files, output_path, selected_checks, report_mode):
        try:
            # 1. Рассчитываем баллы с учётом выбранных типов проверок
            scores = score_maliciousness(results, selected_checks)

            # 2. Генерируем отчёт
            generate_detailed_report(results, scores, output_path, selected_checks, report_mode)

            # 3. Сохраняем сессию
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
                "timestamp": datetime.now().strftime("%d.%m.%Y %H:%M:%S")
            }
            save_last_scan(session)
            self.last_scan = session

            # 4. Обновляем GUI
            self.summary_text.clear()
            self.summary_text.append(f"Последний скан: {session['timestamp']}\n")
            self.summary_text.append(f"Общее количество файлов: {len(scores)}")
        
            avg_score = sum(scores.values()) / len(scores) if scores else 0
            self.summary_text.append(f"Средний балл риска: {avg_score:.2f}")
        
            high_risk = sum(1 for s in scores.values() if s >= 70)
            self.summary_text.append(f"Файлы с высоким риском (≥70): {high_risk}\n")
            self.summary_text.append(f"Использованные проверки: {', '.join(selected_checks)}")

            # 5. Заполняем таблицу результатов
            self.results_table.setRowCount(len(scores))
            for row, (filename, score) in enumerate(scores.items()):
                self.results_table.setItem(row, 0, QTableWidgetItem(filename))
            
                score_item = QTableWidgetItem(f"{score}")
                if score >= 70:
                    score_item.setBackground(QBrush(QColor(220, 50, 50)))  # Красный
                elif score >= 40:
                    score_item.setBackground(QBrush(QColor(255, 165, 0)))  # Оранжевый
                else:
                    score_item.setBackground(QBrush(QColor(50, 200, 50)))  # Зелёный
                self.results_table.setItem(row, 1, score_item)

            # 6. Обновляем детали и графики
            self.file_combo.clear()
            self.file_combo.addItems(scores.keys())
            if scores:
                self.update_details()

            self.generate_charts(scores, results, selected_checks)
            self.generate_interaction_graph(results, files)

            # 7. Активируем кнопку AI-анализа
            self.io_net_button.setEnabled(True)
            self.logger.info("Сканирование успешно завершено")
            QMessageBox.information(self, "Успех", "Сканирование завершено!")

        except Exception as e:
            self.logger.error(f"Ошибка обработки результатов: {str(e)}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка обработки: {str(e)}")
        finally:
            self.scan_button.setEnabled(True)
            self.progress_bar.setValue(100)

    def scan_failed(self, error_msg):
        self.logger.error(f"Сканирование не удалось: {error_msg}")
        QMessageBox.critical(self, "Ошибка", f"Сканирование не удалось: {error_msg}")
        self.scan_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.io_net_button.setEnabled(False)

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

        scores = self.last_scan.get("scores", {})
        self.summary_text.clear()
        self.summary_text.append(f"Последний скан: {self.last_scan.get('timestamp', 'Неизвестно')}\n")
        self.summary_text.append(f"Общее количество отсканированных файлов: {len(scores)}")
        avg_score = sum(scores.values()) / len(scores) if scores else 0
        self.summary_text.append(f"Средний балл риска: {avg_score:.2f}")
        high_risk = sum(1 for s in scores.values() if s >= 70)
        self.summary_text.append(f"Файлы с высоким риском (балл >= 70): {high_risk}\n")
        self.summary_text.append(f"Использованные типы проверок: {', '.join(self.last_scan.get('check_types', []))}")

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

        self.file_combo.clear()
        self.file_combo.addItems(scores.keys())
        if scores:
            self.update_details()

        self.generate_charts(scores, self.last_scan.get("results", {}), self.last_scan.get("check_types", []))
        self.generate_interaction_graph(self.last_scan.get("results", {}), [(f, '') for f in self.last_scan.get("files", [])])
        self.io_net_button.setEnabled(True)

    def _add_finding_to_table(self, finding: str, check_type: str):
        # Парсим строку находки
        match = re.match(r"(?:Line (\d+|-): )?(.*?) \[Type: .*\] \[Reason: (.*?)\] \[Advice: (.*?)\]", finding)
        if not match:
            return
        line_num, snippet, reason, advice = match.groups()
        line_num = line_num if line_num != '-' else 'N/A'
        snippet = snippet.strip() if snippet else 'N/A'
        
        row = self.details_table.rowCount()
        self.details_table.insertRow(row)
        self.details_table.setItem(row, 0, QTableWidgetItem(line_num))
        self.details_table.setItem(row, 1, QTableWidgetItem(check_type))
        self.details_table.setItem(row, 2, QTableWidgetItem(snippet))
        self.details_table.setItem(row, 3, QTableWidgetItem(reason))
        self.details_table.setItem(row, 4, QTableWidgetItem(advice))

    def update_details(self):
        filename = self.file_combo.currentText()
        if not filename or not self.last_scan:
            return

        results = self.last_scan.get("results", {})
        patterns = results.get(filename, {})
        selected_checks = self.last_scan.get("check_types", [])
    
        self.details_table.setRowCount(0)
        seen_findings = set()  # Для уникальности записей по строке и типу
    
        # Только выбранные типы проверок
        if 'regex' in selected_checks and '_checks' in patterns and 'regex' in patterns['_checks']:
            for finding in patterns['_checks']['regex'].get('detailed_findings', []):
                key = (re.search(r"Line (\d+|-):", finding).group(0) if re.search(r"Line (\d+|-):", finding) else 'N/A', 'Regex')
                if key not in seen_findings:
                    self._add_finding_to_table(finding, 'Regex')
                    seen_findings.add(key)
    
        if 'ast' in selected_checks and '_checks' in patterns and 'ast' in patterns['_checks']:
            for finding in patterns['_checks']['ast'].get('detailed_findings', []):
                key = (re.search(r"Line (\d+|-):", finding).group(0) if re.search(r"Line (\d+|-):", finding) else 'N/A', 'AST')
                if key not in seen_findings:
                    self._add_finding_to_table(finding, 'AST')
                    seen_findings.add(key)
    
        # Эвристики только если есть комбинации
        if 'heuristics' in selected_checks:
            for line in patterns.get('detailed_lines', []):
                if re.search(r"\[Type: Heuristics\]", line):
                    key = (re.search(r"Line (\d+|-):", line).group(0) if re.search(r"Line (\d+|-):", line) else 'N/A', 'Heuristics')
                    if key not in seen_findings:
                        self._add_finding_to_table(line, 'Heuristics')
                        seen_findings.add(key)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CodeScannerGUI()
    window.show()
    sys.exit(app.exec_())