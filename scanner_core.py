import ast
import re
import yara
import subprocess
import json
from heuristics import perform_heuristics
from github_utils import get_repository_files
from plugin_runner import run_plugins

def analyze_code(files, yara_rule_source=None, check_types=None):
    """
    Analyzes a list of files using specified checks (AST, regex, YARA, Bandit, heuristics).
    check_types: List of enabled checks ["ast", "regex", "yara", "bandit", "heuristics"].
    If None, all checks are performed.
    """
    if check_types is None:
        check_types = ["ast", "regex", "yara", "bandit", "heuristics"]

    yara_rules = None
    if "yara" in check_types and yara_rule_source:
        try:
            yara_rules = yara.compile(source=yara_rule_source)
        except Exception as e:
            print(f"YARA compilation error: {e}")

    results = {}
    for filename, code in files:
        patterns = {"_code": code}  # Store code for line number extraction
        
        # AST-based checks
        if "ast" in check_types:
            try:
                tree = ast.parse(code)
                patterns["eval_usage"] = any(isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "eval" for node in ast.walk(tree))
                patterns["exec_usage"] = any(isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "exec" for node in ast.walk(tree))
                patterns["subprocess_usage"] = any(
                    isinstance(node, ast.Call) and hasattr(node.func, 'attr') and node.func.attr in ["Popen", "call", "run"]
                    for node in ast.walk(tree)
                )
                patterns["os_system"] = any(
                    isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == "system" 
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"
                    for node in ast.walk(tree)
                )
                patterns["pickle_loads"] = any(
                    isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == "loads" 
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle"
                    for node in ast.walk(tree)
                )
                patterns["subprocess_shell_true"] = any(
                    isinstance(node, ast.Call) and hasattr(node.func, 'attr') 
                    and node.func.attr in ["Popen", "call", "run"]
                    and any(
                        keyword.arg == "shell" 
                        and isinstance(keyword.value, ast.Constant) 
                        and keyword.value.value is True
                        for keyword in node.keywords
                    )
                    for node in ast.walk(tree)
                )
                patterns["insecure_serialization"] = any(
                    isinstance(node, ast.Call) and getattr(node.func, 'attr', None) in ["loads", "load"]
                    and isinstance(node.func.value, ast.Name) 
                    and node.func.value.id in ["pickle", "marshal", "shelve"]
                    for node in ast.walk(tree)
                )
                patterns["input_usage"] = any(
                    isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "input"
                    for node in ast.walk(tree)
                )
                patterns["dynamic_import"] = any(
                    isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "__import__"
                    for node in ast.walk(tree)
                )
            except Exception as e:
                print(f"AST parsing error in {filename}: {e}")

        # Regex-based checks
        if "regex" in check_types:
            patterns["ip_blocking"] = bool(re.search(r"if .*in.*blacklist", code))
            patterns["spam_subscription"] = bool(re.search(r"subscribe.*mail", code, re.IGNORECASE))
            patterns["dangerous_links"] = bool(re.search(r"http[s]?://.*(exe|bat|js|vbs|sh|dll)", code))
            patterns["malicious_download"] = bool(re.search(r"requests\.get\s*\(.*\b(url|path)\b", code))
            patterns["user_data_exfiltration"] = bool(re.search(r"open\s*\(.*\.(txt|csv|log)\)", code))
            patterns["registry_access"] = bool(re.search(r"winreg", code))
            patterns["base64_decode_eval"] = bool(re.search(r"base64\.b64decode\s*\([^)]*\)\s*.*eval\s*\(", code))
            patterns["suspicious_dynamic_exec"] = bool(re.search(r"(compile|exec)\s*\(", code))
            patterns["dangerous_imports"] = any(mod in code for mod in ["socket", "ctypes", "pickle", "marshal", "Crypto"])
            patterns["obfuscated_code"] = len(re.findall(r'\\x[0-9A-Fa-f]{2}', code)) > 20
            patterns["suspicious_file_ops"] = bool(re.search(r"open\s*\(.*[wa]\)", code))
            patterns["dynamic_module_loading"] = bool(re.search(r"importlib\.import_module", code)) or "__import__" in code
            patterns["suspicious_getattr"] = bool(re.search(r"getattr\s*\(.*['\"]", code))
            patterns["hardcoded_credentials"] = bool(re.search(r"(password|secret|api_key)\s*=\s*['\"][^'\"]+['\"]", code, re.IGNORECASE))
            patterns["insecure_protocol"] = bool(re.search(r"http://", code))
            patterns["sql_injection"] = bool(re.search(r"execute\s*\(.*%.*\)", code))
            patterns["reverse_shell"] = bool(re.search(r"socket\.(socket|create_connection)\s*\(", code)) and bool(re.search(r"connect\s*\(\s*\(.*\)\s*\)", code))
            patterns["weak_encryption"] = bool(re.search(r"cryptography\.(md5|sha1)", code, re.IGNORECASE))
            patterns["malicious_comments"] = bool(re.search(r"(backdoor|malware|exploit|keylogger|ransom)", code, re.IGNORECASE))
            patterns["hidden_process"] = bool(re.search(r"CREATE_NO_WINDOW|SW_HIDE", code))
            patterns["camera_access"] = bool(re.search(r"cv2\.VideoCapture|pygame\.camera", code))
            patterns["microphone_access"] = bool(re.search(r"sounddevice\.rec|pyaudio\.PyAudio", code))
            patterns["dropper_code"] = bool(re.search(r"requests\.get\(.*\)\.content.*exec\(|urllib\.request\.urlopen\(.*\)\.read\(\)", code))
            patterns["code_injection"] = bool(re.search(r"ctypes\.windll|WriteProcessMemory", code))
            patterns["file_permission_changes"] = bool(re.search(r"os\.chmod|os\.chown", code))
            patterns["in_memory_execution"] = bool(re.search(r"exec\(compile\(|eval\(compile\(|exec\(.*decode\(['\"]base64", code))
            patterns["env_variable_usage"] = bool(re.search(r"os\.getenv|os\.environ\.get", code)) and not bool(re.search(r"default=os\.getenv\(", code))

        # Bandit checks
        if "bandit" in check_types:
            bandit_vulns = detect_bandit_vulnerabilities(code)
            patterns.update(bandit_vulns)

        # YARA checks
        if "yara" in check_types and yara_rules:
            try:
                patterns["yara_match"] = bool(yara_rules.match(data=code))
            except Exception as e:
                print(f"YARA error in {filename}: {e}")
                patterns["yara_match"] = False
        else:
            patterns["yara_match"] = False

        # Heuristics checks
        if "heuristics" in check_types:
            extra_patterns = perform_heuristics(filename, code, run_plugins)
            patterns.update(extra_patterns)

        results[filename] = patterns
    return results

def detect_bandit_vulnerabilities(code):
    """Implementation of Bandit checks via AST and regex"""
    vulns = {}
    
    try:
        tree = ast.parse(code)
    except Exception as e:
        return vulns

    # B101: assert_used
    vulns['assert_used'] = any(isinstance(node, ast.Assert) for node in ast.walk(tree))

    # B102: exec_used
    vulns['exec_used'] = any(
        isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "exec"
        for node in ast.walk(tree)
    )

    # B103: set_bad_file_permissions
    vulns['bad_file_perms'] = bool(re.search(
        r'os\.chmod\s*\(.*0o?777|0o?666', code
    ))

    # B104: bind_all_interfaces
    vulns['bind_all_interfaces'] = any(
        isinstance(node, ast.Call) and
        getattr(node.func, 'attr', None) == 'bind' and
        any(
            kw.arg == 'host' and
            isinstance(kw.value, ast.Str) and
            kw.value.s in ('0.0.0.0', '::')
            for kw in node.keywords
        )
        for node in ast.walk(tree)
    )

    # B105: hardcoded_password_string
    vulns['hardcoded_password'] = bool(re.search(
        r'(password|passwd|pwd|secret|token)\s*=\s*[\'"][^\'"]+[\'"]',
        code, re.IGNORECASE
    ))

    # B106: hardcoded_tmp_directory
    vulns['hardcoded_tmp'] = bool(re.search(
        r'(/tmp|/var/tmp|C:\\TEMP)(\\\\|/)[^\'"]+',
        code, re.IGNORECASE
    ))

    # B107: hardcoded_ssl_cert
    vulns['hardcoded_ssl_cert'] = bool(re.search(
        r'context\.load_cert_chain\([\'"]', code
    ))

    # B108: hardcoded_aws_keys
    vulns['aws_keys'] = bool(re.search(
        r'(AKIA|ASIA)[A-Z0-9]{16}', code
    ))

    # B301: pickle
    vulns['pickle_used'] = any(
        isinstance(node, (ast.Import, ast.ImportFrom)) and
        any(alias.name == 'pickle' for alias in node.names)
        for node in ast.walk(tree)
    )

    # B302: marshal
    vulns['marshal_used'] = any(
        isinstance(node, ast.Call) and
        getattr(node.func, 'id', None) == 'loads' and
        any(
            isinstance(parent, ast.Attribute) and 
            parent.attr == 'marshal' 
            for parent in ast.walk(tree)
        )
        for node in ast.walk(tree)
    )

    # B303: md5
    vulns['md5_used'] = any(
        isinstance(node, ast.Call) and
        getattr(node.func, 'attr', None) == 'md5' and
        getattr(node.func.value, 'id', None) == 'hashlib'
        for node in ast.walk(tree)
    )

    # B304: cgi
    vulns['cgi_used'] = any(
        'cgi' in [alias.name for alias in node.names]
        for node in ast.walk(tree) 
        if isinstance(node, ast.Import)
    )

    # B305: ftplib
    vulns['ftplib_used'] = any(
        isinstance(node, ast.Import) and
        any(alias.name == 'ftplib' for alias in node.names)
        for node in ast.walk(tree)
    )

    # B306: mktemp
    vulns['mktemp_used'] = any(
        isinstance(node, ast.Call) and
        getattr(node.func, 'id', None) == 'mktemp' and
        any(
            isinstance(parent, ast.Attribute) and 
            parent.attr == 'tempfile' 
            for parent in ast.walk(tree)
        )
        for node in ast.walk(tree)
    )

    # B307: eval
    vulns['eval_used'] = any(
        isinstance(node, ast.Call) and 
        getattr(node.func, 'id', None) == "eval"
        for node in ast.walk(tree)
    )

    # B308: mark_safe
    vulns['mark_safe_used'] = any(
        isinstance(node, ast.Call) and
        getattr(node.func, 'id', None) == 'mark_safe'
        for node in ast.walk(tree)
    )

    # B309: httpsconnection
    vulns['httpsconnection_used'] = bool(re.search(
        r'HTTPSConnection\s*\(', code
    ))

    # B310: urllib_urlopen
    vulns['urlopen_used'] = bool(re.search(
        r'urllib\.(request\.)?urlopen\s*\(', code
    ))

    # B311: random
    vulns['random_used'] = any(
        isinstance(node, ast.Import) and
        any(alias.name == 'random' for alias in node.names)
        for node in ast.walk(tree)
    )

    # B312: telnetlib
    vulns['telnetlib_used'] = any(
        isinstance(node, ast.ImportFrom) and
        node.module == 'telnetlib'
        for node in ast.walk(tree)
    )

    # B313: xml.etree.cElementTree
    vulns['cElementTree_used'] = bool(re.search(
        r'from\s+xml\.etree\s+import\s+cElementTree', code
    ))

    # B314: paramiko
    vulns['paramiko_insecure'] = any(
        isinstance(node, ast.Call) and
        getattr(node.func, 'attr', None) == 'set_missing_host_key_policy' and
        getattr(node.func.value, 'id', None) == 'client'
        for node in ast.walk(tree)
    )

    # B501: ssl_with_bad_version
    vulns['ssl_bad_version'] = bool(re.search(
        r'PROTOCOL_(SSLv2|SSLv3|TLSv1|TLSv1\.1)\b', code
    ))

    # B502: ssl_with_bad_defaults
    vulns['ssl_bad_defaults'] = bool(re.search(
        r'OP_NO_SSLv2|OP_NO_SSLv3', code
    ))

    # B601: paramiko_calls
    vulns['paramiko_exec_command'] = bool(re.search(
        r'\.exec_command\s*\(', code
    ))

    # B602: subprocess_popen_with_shell_equals_true
    vulns['subprocess_shell_true'] = any(
        isinstance(node, ast.Call) and
        getattr(node.func, 'attr', None) in ['Popen', 'run', 'call'] and
        any(
            kw.arg == 'shell' and
            isinstance(kw.value, ast.Constant) and
            kw.value.value is True
            for kw in node.keywords
        )
        for node in ast.walk(tree)
    )

    # B603: subprocess_without_shell_equals_true
    vulns['subprocess_without_shell'] = bool(re.search(
        r'subprocess\.(Popen|run|call)\(.*shell\s*=\s*False', code
    ))

    # B604: any_other_function_with_shell_equals_true
    vulns['other_shell_true'] = bool(re.search(
        r'\b(shell|executable)\s*=\s*True', code
    )) and not vulns.get('subprocess_shell_true', False)

    # B605: start_process_with_partial_path
    vulns['partial_path_process'] = bool(re.search(
        r'(Popen|run|call)\([\'"][^/\\][^\'"]+[\'"]', code
    ))

    # B606: assert_used
    vulns['assert_used'] = vulns.get('assert_used', False) or bool(
        re.search(r'\bassert\b', code
    ))

    # B607: start_process_with_a_shell
    vulns['shell_process'] = bool(re.search(
        r'(Popen|run|call)\(.*, shell=True', code
    ))

    # B608: hardcoded_sql_expressions
    vulns['hardcoded_sql'] = bool(re.search(
        r'(SELECT|INSERT|UPDATE|DELETE)\s+.*(FROM|INTO|SET|WHERE)',
        code, re.IGNORECASE | re.DOTALL
    ))

    # B609: linux_commands_wildcard_injection
    vulns['wildcard_injection'] = bool(re.search(
        r'(rm|ls|chmod|chown)\s+.*[\*\?\[\]]', code
    ))

    # B610: django_extra_used
    vulns['django_extra_used'] = bool(re.search(
        r'\.extra\s*\(', code
    ))

    # B611: django_rawsql_used
    vulns['django_rawsql_used'] = bool(re.search(
        r'\.raw\s*\(|RawSQL\s*\(', code
    ))

    # B612: logging_config_insecure_listen
    vulns['logging_insecure'] = bool(re.search(
        r'logging\.basicConfig\(.*handlers\s*=\s*\[.*SocketHandler', code
    ))

    # B701: jinja2_autoescape_false
    vulns['jinja2_autoescape_off'] = bool(re.search(
        r'Environment\s*\(.*autoescape\s*=\s*False', code
    ))

    return vulns

def score_maliciousness(results):
    """
    Enhanced scoring system considering all patterns
    """
    scoring_rules = {
        # Bandit rules
        'assert_used': 15,
        'exec_used': 90,
        'bad_file_perms': 60,
        'bind_all_interfaces': 85,
        'hardcoded_password': 95,
        'hardcoded_tmp': 40,
        'hardcoded_ssl_cert': 80,
        'aws_keys': 100,
        'pickle_used': 70,
        'marshal_used': 75,
        'md5_used': 65,
        'cgi_used': 50,
        'ftplib_used': 45,
        'mktemp_used': 55,
        'eval_used': 85,
        'mark_safe_used': 60,
        'httpsconnection_used': 35,
        'urlopen_used': 50,
        'random_used': 20,
        'telnetlib_used': 65,
        'cElementTree_used': 30,
        'paramiko_insecure': 75,
        'ssl_bad_version': 80,
        'ssl_bad_defaults': 70,
        'paramiko_exec_command': 60,
        'subprocess_shell_true': 85,
        'subprocess_without_shell': 10,
        'other_shell_true': 50,
        'partial_path_process': 45,
        'shell_process': 75,
        'hardcoded_sql': 65,
        'wildcard_injection': 55,
        'django_extra_used': 40,
        'django_rawsql_used': 50,
        'logging_insecure': 60,
        'jinja2_autoescape_off': 70,
        
        # Critical risks (60-100)
        "yara_match": 100,
        "reverse_shell": 95,
        "code_injection": 90,
        "dropper_code": 85,
        "in_memory_execution": 80,
        "malicious_download": 75,

        # High risks (40-59)
        "hardcoded_credentials": 55,
        "sql_injection": 50,
        "subprocess_shell_true": 45,
        "registry_access": 40,
        "dynamic_module_loading": 40,

        # Medium risks (20-39)
        "eval_usage": 35,
        "exec_usage": 35,
        "os_system": 30,
        "dangerous_links": 25,
        "pickle_loads": 20,
        "insecure_serialization": 20,

        # Low risks (1-19)
        "obfuscated_code": 15,
        "suspicious_file_ops": 12,
        "input_usage": 10,
        "weak_encryption": 8,
        "malicious_comments": 5,

        # Heuristic checks
        "ml_suspicion": lambda x: int(x * 0.3),
        "api_keys": lambda x: 55 if any(v["found"] for v in x.values()) else 0,
        "encryption": lambda x: 30 if any(v["found"] for v in x.values()) else 0,
        "network": lambda x: 40 if any(v["found"] for v in x.values()) else 0,
        "hardware": lambda x: 30 if any(v["found"] for v in x.values()) else 0,
        "shell_injection": lambda x: 45 if x.get("shell_injection", {}).get("found") else 0,
        "sql_injection": lambda x: 50 if x.get("sql_injection", {}).get("found") else 0,

        # Dynamic rules
        "plugin_": lambda x: min(x * 2, 25),
    }

    scores = {}
    for filename, patterns in results.items():
        score = 0
        
        # Main patterns
        for pattern, value in patterns.items():
            if pattern in ["_code", "detailed_lines"]:
                continue  # Skip non-scored patterns
            if isinstance(value, bool) and value:
                for rule in scoring_rules:
                    if pattern.startswith(rule):
                        weight = scoring_rules[rule]
                        if callable(weight):
                            score += weight(value)
                        else:
                            score += weight
                        break
            elif isinstance(value, dict):
                for rule in scoring_rules:
                    if pattern == rule:
                        weight = scoring_rules[rule]
                        if callable(weight):
                            score += weight(value)
                        break
            elif pattern == "ml_suspicion" and isinstance(value, (int, float)):
                score += scoring_rules["ml_suspicion"](value)

        # Special cases
        if patterns.get("camera_access") or patterns.get("microphone_access"):
            score += 30
        if patterns.get("dynamic_import") and patterns.get("suspicious_getattr"):
            score += 25

        scores[filename] = max(0, min(score, 100))

    return scores

def perform_scan(repo_url, token, yara_rule_source, check_types=None):
    """
    Updated scan function with selective check types
    """
    files = get_repository_files(repo_url, token)
    if not files:
        raise ValueError("No Python files found in repository.")
    
    results = analyze_code(files, yara_rule_source, check_types)
    scores = score_maliciousness(results)
    
    return results, scores, files