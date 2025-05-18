import re
import ast
import json
import yara
import multiprocessing
from pathlib import Path
from typing import List, Dict, Any, Tuple
from heuristics import HeuristicAnalyzer, detailed_extract_suspicious_lines

class CodeScanner:
    def __init__(self, patterns_file: str = "patterns.json", yara_rules: str = "rules.yar"):
        self.yara_rules_path = yara_rules  # Сохраняем путь к YARA-правилам
        try:
            with open(patterns_file, 'r', encoding='utf-8-sig') as f:
                self.patterns = json.load(f)
        except FileNotFoundError:
            print(f"Patterns file {patterns_file} not found.")
            self.patterns = []
        except json.JSONDecodeError:
            print(f"Invalid JSON in {patterns_file}.")
            self.patterns = []
        
        self.yara_rules = None
        if Path(yara_rules).exists():
            try:
                self.yara_rules = yara.compile(yara_rules)
            except yara.Error as e:
                print(f"Failed to compile YARA rules: {e}")
        self.heuristic_analyzer = HeuristicAnalyzer()

    def regex_check(self, code: str, filename: str) -> Dict[str, Any]:
        findings = {'_code': code, 'detailed_findings': []}
        for pattern in self.patterns:
            if pattern.get('pattern') and pattern['pattern'] != 'null':
                try:
                    regex = re.compile(pattern['pattern'], re.IGNORECASE)
                    matches = []
                    for i, line in enumerate(code.splitlines(), 1):
                        if regex.search(line):
                            matches.append((i, line.strip()))
                    if matches:
                        findings[pattern['key']] = True
                        findings['detailed_findings'].extend([
                            f"Line {line_num}: {line} [Type: Regex] [Reason: {pattern['description']}] [Advice: {pattern['advice']}]"
                            for line_num, line in matches
                        ])
                except re.error:
                    print(f"Ошибка в regex паттерне {pattern['key']}")
        return findings

    def ast_check(self, code: str, filename: str) -> Dict[str, Any]:
        findings = {'_code': code, 'detailed_findings': []}
        seen_lines = set()  # Для предотвращения дублирования по строкам
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                for pattern in self.patterns:
                    if self._check_ast_node(node, pattern, code):
                        line = getattr(node, 'lineno', 1)
                        if line in seen_lines:
                            continue  # Пропускаем, если строка уже обработана
                        seen_lines.add(line)
                        snippet = code.splitlines()[line - 1].strip() if line <= len(code.splitlines()) else "N/A"
                        findings[pattern['key']] = True
                        findings['detailed_findings'].append(
                            f"Line {line}: {snippet} [Type: AST] [Reason: {pattern['description']}] [Advice: {pattern['advice']}]"
                        )
        except SyntaxError:
            print(f"Синтаксическая ошибка в {filename}")
        return findings

    def yara_check(self, code: str, filename: str) -> Dict[str, Any]:
        findings = {'_code': code, 'detailed_findings': []}
        if self.yara_rules is None and Path(self.yara_rules_path).exists():
            try:
                self.yara_rules = yara.compile(self.yara_rules_path)
            except yara.Error as e:
                print(f"Ошибка компиляции YARA: {e}")
                return findings
        
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(data=code.encode('utf-8'))
                for match in matches:
                    findings['yara_match'] = True
                    findings['detailed_findings'].append(
                        f"[Type: YARA] [Reason: Совпадение с правилом {match.rule}] [Advice: Проверьте YARA-правило]"
                    )
            except Exception as e:
                print(f"Ошибка YARA в {filename}: {e}")
        return findings

    def analyze_file(self, filename: str, code: str, check_types: List[str]) -> Dict[str, Any]:
        results = {
            '_code': code,
            '_checks': {},
            'detailed_findings': [],
            'detailed_lines': []
        }

        # Выполняем только выбранные проверки
        if 'regex' in check_types:
            results['_checks']['regex'] = self.regex_check(code, filename)
            results['detailed_findings'].extend(results['_checks']['regex']['detailed_findings'])
        
        if 'ast' in check_types:
            results['_checks']['ast'] = self.ast_check(code, filename)
            results['detailed_findings'].extend(results['_checks']['ast']['detailed_findings'])
        
        if 'yara' in check_types:
            results['_checks']['yara'] = self.yara_check(code, filename)
            results['detailed_findings'].extend(results['_checks']['yara']['detailed_findings'])

        # Эвристики только если есть данные других проверок
        if 'heuristics' in check_types:
            heuristic_data = {
                'regex': results['_checks'].get('regex', {}),
                'ast': results['_checks'].get('ast', {}),
                'yara': results['_checks'].get('yara', {})
            }
            heuristic_results = self.heuristic_check(code, filename, heuristic_data)
            results.update(heuristic_results)

        return results

    def _check_ast_node(self, node: ast.AST, pattern: Dict[str, Any], code: str) -> bool:
        if pattern.get('pattern') and pattern['pattern'] != 'null':
            try:
                regex = re.compile(pattern['pattern'], re.IGNORECASE)
                line = getattr(node, 'lineno', None)
                if line:
                    lines = code.splitlines()
                    if 1 <= line <= len(lines):  # Проверка границ
                        snippet = lines[line - 1].strip()
                        return bool(regex.search(snippet))
            except re.error:
                pass
        return False

    def heuristic_check(self, code: str, filename: str, base_results: Dict[str, Any]) -> Dict[str, Any]:
        results = {
            'heuristics': {},
            'detailed_lines': []
        }

        # 1. Комбинированные эвристики (только если есть данные от других проверок)
        triggered_patterns = set()
        for check_type, data in base_results.items():
            for pattern_key, is_detected in data.items():
                if is_detected and isinstance(is_detected, bool):
                    triggered_patterns.add(pattern_key)

        # Применяем комбинации из heuristics.py
        for combo in self.heuristic_analyzer.combinations:
            if all(key in triggered_patterns for key in combo['keys']):
                results['heuristics'][combo['key']] = True
                results['detailed_lines'].append(
                    f"Line -: N/A [Type: Heuristics] [Reason: {combo['description']} "
                    f"[Advice: {combo['advice']}]"
                )

        # 2. Детекция подозрительных строк (независимая эвристика)
        results['detailed_lines'].extend(detailed_extract_suspicious_lines(code))
    
        return results

def perform_scan(files: List[Tuple[str, str]], yara_source: str = None, check_types: List[str] = None) -> Dict[str, Any]:
    if check_types is None:
        check_types = ['regex', 'ast', 'yara', 'heuristics']
    scanner = CodeScanner(yara_rules=yara_source if yara_source else "rules.yar")
    results = {}
    for filename, code in files:
        results[filename] = scanner.analyze_file(filename, code, check_types)
    return results

def analyze_code(files: List[Tuple[str, str]], yara_source: str = None, check_types: List[str] = None) -> Dict[str, Any]:
    return perform_scan(files, yara_source, check_types)

def score_maliciousness(results: Dict[str, Any], check_types: List[str]) -> Dict[str, float]:
    scores = {}
    weights = {  # Веса методов (сумма = 100)
        'regex': 30,
        'ast': 40,
        'yara': 50,
        'heuristics': 20
    }

    for filename, data in results.items():
        score = 0
        
        # Базовые проверки
        if 'regex' in check_types and '_checks' in data and 'regex' in data['_checks']:
            for pattern_key, detected in data['_checks']['regex'].items():
                if detected and pattern_key != '_code':
                    score += weights['regex'] * 0.3  # Пример: 30% от веса метода

        if 'ast' in check_types and '_checks' in data and 'ast' in data['_checks']:
            for pattern_key, detected in data['_checks']['ast'].items():
                if detected and pattern_key != '_code':
                    score += weights['ast'] * 0.4  # AST авторитетнее Regex

        if 'yara' in check_types and '_checks' in data and 'yara' in data['_checks']:
            for pattern_key, detected in data['_checks']['yara'].items():
                if detected and pattern_key != '_code':
                    score += weights['yara'] * 0.5  # YARA имеет высокий вес

        # Эвристики (добавляем только если есть комбинации)
        if 'heuristics' in check_types:
            for heuristic_key, detected in data['heuristics'].items():
                if detected:
                    score += weights['heuristics'] * 0.5  # Комбинации критичны

        # Ограничение и нормализация
        scores[filename] = min(100, round(score, 2))
    
    return scores