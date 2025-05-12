import ast
import re
import yara
from heuristics import perform_heuristics
from github_utils import get_repository_files
from plugin_runner import run_plugins

def analyze_code(files, yara_rule_source=None):
    """
    Анализирует список файлов, используя базовые проверки (через AST/regex) 
    и объединяя их с расширенными эвристиками.
    """
    yara_rules = None
    if yara_rule_source:
        try:
            yara_rules = yara.compile(source=yara_rule_source)
        except Exception as e:
            print(f"YARA compilation error: {e}")
    
    results = {}
    for filename, code in files:
        try:
            tree = ast.parse(code)
        except Exception as e:
            print(f"AST parsing error in {filename}: {e}")
            continue
        
        patterns = {}
        # Базовые проверки через AST/regex
        patterns["eval_usage"] = any(isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "eval" for node in ast.walk(tree))
        patterns["exec_usage"] = any(isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "exec" for node in ast.walk(tree))
        patterns["subprocess_usage"] = any(
            isinstance(node, ast.Call) and hasattr(node.func, 'attr') and node.func.attr in ["Popen", "call", "run"]
            for node in ast.walk(tree)
        )
        patterns["ip_blocking"] = bool(re.search(r"if .*in.*blacklist", code))
        patterns["spam_subscription"] = bool(re.search(r"subscribe.*mail", code, re.IGNORECASE))
        patterns["dangerous_links"] = bool(re.search(r"http[s]?://.*(exe|bat|js|vbs|sh)", code))
        patterns["malicious_download"] = bool(re.search(r"requests\.get\s*\(.*\b(url|path)\b", code))
        patterns["user_data_exfiltration"] = bool(re.search(r"open\s*\(.*\.(txt|csv)\)", code))
        patterns["registry_access"] = bool(re.search(r"winreg", code))
        patterns["base64_decode_eval"] = bool(re.search(r"base64\.b64decode\s*\([^)]*\)\s*.*eval\s*\(", code))
        patterns["suspicious_dynamic_exec"] = bool(re.search(r"(compile|exec)\s*\(", code))
        patterns["dangerous_imports"] = any(mod in code for mod in ["socket", "ctypes", "pickle", "marshal"])
        patterns["obfuscated_code"] = len(re.findall(r'\\x[0-9A-Fa-f]{2}', code)) > 20
        patterns["suspicious_file_ops"] = bool(re.search(r"open\s*\(.*[wa]\)", code))
        patterns["dynamic_module_loading"] = bool(re.search(r"importlib\.import_module", code)) or "__import__" in code
        patterns["suspicious_getattr"] = bool(re.search(r"getattr\s*\(.*['\"]", code))
        
        if yara_rules:
            try:
                patterns["yara_match"] = bool(yara_rules.match(data=code))
            except Exception as e:
                print(f"YARA error in {filename}: {e}")
                patterns["yara_match"] = False
        else:
            patterns["yara_match"] = False
        
        # Расширенные эвристики с дополнительными проверками
        extra_patterns = perform_heuristics(filename, code, run_plugins)
        patterns.update(extra_patterns)
        
        results[filename] = patterns
    return results

def score_maliciousness(results):
    """
    Вычисляет суммарный балл подозрительности для каждого файла.
    """
    scores = {}
    for file, patterns in results.items():
        score = 0
        if patterns.get("eval_usage"):
            score += 30
        if patterns.get("exec_usage"):
            score += 30
        if patterns.get("subprocess_usage"):
            score += 35
        if patterns.get("ip_blocking"):
            score += 40
        if patterns.get("yara_match"):
            score += 50
        if patterns.get("spam_subscription"):
            score += 25
        if patterns.get("dangerous_links"):
            score += 45
        if patterns.get("malicious_download"):
            score += 50
        if patterns.get("user_data_exfiltration"):
            score += 60
        if patterns.get("registry_access"):
            score += 55
        if patterns.get("base64_decode_eval"):
            score += 40
        if patterns.get("suspicious_dynamic_exec"):
            score += 20
        if patterns.get("dangerous_imports"):
            score += 20
        if patterns.get("obfuscated_code"):
            score += 30
        if patterns.get("suspicious_file_ops"):
            score += 25
        if patterns.get("dynamic_module_loading"):
            score += 30
        if patterns.get("suspicious_getattr"):
            score += 15
        
        for group in ["api_keys", "encryption", "network", "hardware"]:
            group_data = patterns.get(group, {})
            for key, info in group_data.items():
                if isinstance(info, dict) and info.get("found"):
                    if group == "encryption":
                        score += 15 if key != "xor_usage" else 10
                    elif group == "network":
                        score += 10 if key == "socket_creation" else 15
                    elif group == "hardware":
                        score += 30 if key in ["camera_access", "microphone_access"] else 25
                    else:
                        score += 20
        
        # Дополнительные проверки
        for key in ["shell_injection", "sql_injection"]:
            info = patterns.get(key)
            if info and info.get("found"):
                score += 20
        
        ml_score = int(patterns.get("ml_suspicion", 0) * 0.3)
        score += ml_score
        
        for key, value in patterns.items():
            if key.startswith("plugin_") and value:
                score += 15
        
        scores[file] = score
    return scores

def perform_scan(repo_url, token, yara_rule_source):
    """
    Выполняет сканирование репозитория: получение файлов, анализ кода и подсчёт баллов.
    """
    files = get_repository_files(repo_url, token)
    if not files:
        raise ValueError("No Python files found in repository.")
    results = analyze_code(files, yara_rule_source)
    scores = score_maliciousness(results)
    return results, scores, files
