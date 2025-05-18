import re
import math
from typing import List, Dict, Any

class HeuristicAnalyzer:
    def __init__(self):
        self.combinations = [
            {
                'keys': ['eval_usage', 'hardcoded_credentials'],
                'description': 'Комбинация eval() и захардкоденных учетных данных',
                'advice': 'Избегайте eval, используйте безопасное хранение учетных данных',
                'severity': 'Critical',
                'confidence': 0.98,
                'score': 25
            },
            {
                'keys': ['shell_injection', 'dynamic_code_execution'],
                'description': 'Инъекция команд с динамическим выполнением кода',
                'advice': 'Используйте безопасные методы выполнения команд',
                'severity': 'Critical',
                'confidence': 0.95,
                'score': 30
            },
            {
                'keys': ['hardcoded_credentials', 'shell_injection'],
                'description': 'Учетные данные и инъекция команд',
                'advice': 'Храните учетные данные безопасно, избегайте shell-команд',
                'severity': 'Critical',
                'confidence': 0.97,
                'score': 28
            },
            {
                'keys': ['eval_usage', 'shell_injection'],
                'description': 'Eval() с инъекцией команд',
                'advice': 'Избегайте eval и shell-команд',
                'severity': 'Critical',
                'confidence': 0.96,
                'score': 27
            },
            {
                'keys': ['hardcoded_credentials', 'network'],
                'description': 'Учетные данные и сетевые операции',
                'advice': 'Храните учетные данные безопасно, проверьте сетевые вызовы',
                'severity': 'High',
                'confidence': 0.94,
                'score': 22
            },
            {
                'keys': ['dynamic_code_execution', 'network'],
                'description': 'Динамическое выполнение и сетевые операции',
                'advice': 'Ограничьте динамическое выполнение, проверьте сетевые вызовы',
                'severity': 'High',
                'confidence': 0.93,
                'score': 20
            },
            {
                'keys': ['shell_injection', 'network'],
                'description': 'Инъекция команд и сетевые операции',
                'advice': 'Используйте безопасные команды, проверьте сетевые вызовы',
                'severity': 'High',
                'confidence': 0.92,
                'score': 21
            },
            {
                'keys': ['eval_usage', 'insecure_serialization'],
                'description': 'Eval() с небезопасной сериализацией',
                'advice': 'Избегайте eval и небезопасных модулей (pickle, marshal)',
                'severity': 'Critical',
                'confidence': 0.95,
                'score': 26
            },
            {
                'keys': ['hardcoded_credentials', 'insecure_serialization'],
                'description': 'Учетные данные и небезопасная сериализация',
                'advice': 'Храните учетные данные безопасно, избегайте pickle/marshal',
                'severity': 'High',
                'confidence': 0.93,
                'score': 23
            },
            {
                'keys': ['dynamic_code_execution', 'yara_match'],
                'description': 'Динамическое выполнение и YARA-совпадение',
                'advice': 'Ограничьте динамическое выполнение, проверьте YARA-сигнатуры',
                'severity': 'Critical',
                'confidence': 0.97,
                'score': 29
            },
            {
                'keys': ['shell_injection', 'yara_match'],
                'description': 'Инъекция команд и YARA-совпадение',
                'advice': 'Используйте безопасные команды, проверьте YARA-сигнатуры',
                'severity': 'Critical',
                'confidence': 0.96,
                'score': 28
            },
            {
                'keys': ['hardcoded_credentials', 'yara_match'],
                'description': 'Учетные данные и YARA-совпадение',
                'advice': 'Храните учетные данные безопасно, проверьте YARA-сигнатуры',
                'severity': 'High',
                'confidence': 0.94,
                'score': 24
            },
            {
                'keys': ['eval_usage', 'network', 'yara_match'],
                'description': 'Eval(), сетевые операции и YARA-совпадение',
                'advice': 'Избегайте eval, проверьте сетевые вызовы и YARA-сигнатуры',
                'severity': 'Critical',
                'confidence': 0.99,
                'score': 32
            },
            {
                'keys': ['shell_injection', 'network', 'yara_match'],
                'description': 'Инъекция команд, сетевые операции и YARA-совпадение',
                'advice': 'Используйте безопасные команды, проверьте сетевые вызовы и YARA',
                'severity': 'Critical',
                'confidence': 0.98,
                'score': 31
            },
            {
                'keys': ['dynamic_code_execution', 'insecure_serialization', 'network'],
                'description': 'Динамическое выполнение, небезопасная сериализация и сеть',
                'advice': 'Ограничьте динамическое выполнение, избегайте pickle, проверьте сеть',
                'severity': 'Critical',
                'confidence': 0.97,
                'score': 30
            }
        ]

    def analyze(self, code: str, patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        found_keys = {p['key'] for p in patterns if p.get('key')}

        for combo in self.combinations:
            if all(key in found_keys for key in combo['keys']):
                results.append({
                    'key': '_'.join(combo['keys']),
                    'description': combo['description'],
                    'advice': combo['advice'],
                    'severity': combo['severity'],
                    'confidence': combo['confidence'],
                    'score': float(combo['score'])  # Явное приведение к float
                })

        for pattern in patterns:
            results.append({
                'key': pattern['key'],
                'description': pattern['description'],
                'advice': pattern['advice'],
                'severity': pattern.get('severity', 'Medium'),
                'confidence': pattern.get('confidence', 0.9),
                'score': float(pattern.get('score', 10.0))  # Явное приведение к float
            })

        return results

def detailed_extract_suspicious_lines(code: str) -> List[str]:
    suspicious_lines = []
    for i, line in enumerate(code.splitlines(), 1):
        line = line.strip()
        if not line:
            continue

        if len(line) > 200:
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Long line, possible obfuscation] [Advice: Review content]")
        if re.search(r'[A-Za-z0-9+/=]{20,}', line):
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Possible base64 string] [Advice: Decode and verify]")
        if re.search(r'(password|passwd|pwd|secret|token|key)\s*=\s*[\'\"][^\'\"]+[\'\"]', line, re.IGNORECASE):
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Possible credentials] [Advice: Use secure storage]")
        if re.search(r'(eval|exec|system|subprocess|os\.system|__import__)\s*\(', line, re.IGNORECASE):
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Suspicious function call] [Advice: Verify call safety]")
        if re.search(r'(http|https|ftp)://[\w\-\.]+|(\d{1,3}\.){3}\d{1,3}', line, re.IGNORECASE):
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Suspicious URL or IP] [Advice: Verify destination]")
        if re.search(r'\\x[0-9a-fA-F]{2}', line):
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Hex encoding] [Advice: Check decoded content]")
        if re.search(r'(pickle\.loads|marshal\.loads|shelve\.open)\s*\(', line, re.IGNORECASE):
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Insecure serialization] [Advice: Avoid pickle/marshal]")
        if re.search(r'(socket\.|http\.|urllib\.|requests\.)\w+\s*\(', line, re.IGNORECASE):
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Suspicious network operation] [Advice: Verify destination]")
        if re.search(r'(camera|microphone|gps|location)\w*\s*(=|\()', line, re.IGNORECASE):
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: Hardware resource access] [Advice: Verify legitimacy]")
        if len(line) > 20 and calculate_entropy(line) > 4.5:
            suspicious_lines.append(f"Line {i}: {line} [Type: Heuristics] [Reason: High entropy, possible encryption] [Advice: Review content]")

    return suspicious_lines

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy