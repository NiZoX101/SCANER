import openpyxl
from openpyxl.styles import Font, PatternFill
import matplotlib.pyplot as plt
import pandas as pd
import plotly.express as px

def generate_report(results, scores, output_file):
    """
    Генерирует расширённый отчёт:
      - Excel-файл с двумя листами:
         Лист 1: "Общий отчёт" – по каждому файлу итоговый балл и краткое описание обнаруженных типов.
         Лист 2: "Подробности" – каждая обнаруженная проверка выведена в отдельной строке.
      - Статический график с matplotlib и интерактивный график с plotly.
    """
    wb = openpyxl.Workbook()
    
    # Лист 1: Общий отчёт
    ws1 = wb.active
    ws1.title = "Общий отчёт"
    ws1.append(["File", "Maliciousness Score", "Краткое описание"])
    header_font = Font(bold=True)
    for cell in ws1[1]:
        cell.font = header_font
    for file, score in scores.items():
        brief = []
        res = results[file]
        if res.get("detailed_lines"):
            brief.append(f"Строк: {len(res['detailed_lines'])}")
        for group in ["api_keys", "encryption", "network", "hardware"]:
            group_data = res.get(group, {})
            for key, info in group_data.items():
                if isinstance(info, dict) and info.get("found"):
                    brief.append(key)
        ws1.append([file, score, "; ".join(brief)])
    
    # Лист 2: Подробности
    ws2 = wb.create_sheet(title="Подробности")
    ws2.append(["File", "Тип проверки", "Описание", "Совет", "Найденное значение"])
    for cell in ws2[1]:
        cell.font = header_font
    for file, res in results.items():
        # Подробные строки
        for line in res.get("detailed_lines", []):
            ws2.append([file, "Строка", "", line, ""])
        # API ключи, Шифрование, Сетевые операции, Доступ и дополнительные проверки
        for group in ["api_keys", "encryption", "network", "hardware"]:
            for key, info in res.get(group, {}).items():
                if isinstance(info, dict) and info.get("found"):
                    ws2.append([file, key, info.get("description", ""), info.get("advice", ""), info.get("match", "")])
        # Дополнительные проверки (shell, SQL)
        for key in ["shell_injection", "sql_injection"]:
            info = res.get(key)
            if info and info.get("found"):
                ws2.append([file, key, info.get("description", ""), info.get("advice", ""), ""])
        # Плагины
        for key, value in res.items():
            if key.startswith("plugin_"):
                ws2.append([file, key, "Плагин", "", value])
    
    wb.save(output_file)
    
    # Статический график с matplotlib
    plt.figure(figsize=(12,6))
    plt.bar(list(scores.keys()), list(scores.values()), color='skyblue')
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Maliciousness Score")
    plt.title("Threat Analysis per File")
    plt.tight_layout()
    plt.savefig("report.png")
    
    # Интерактивный график с plotly
    df = pd.DataFrame({
        "File": list(scores.keys()),
        "Score": list(scores.values())
    })
    fig = px.bar(df, x="File", y="Score", hover_data=["File"], title="Threat Score per File (Interactive)")
    fig.write_html("report.html")
