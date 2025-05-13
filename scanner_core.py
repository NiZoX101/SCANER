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
    Returns: Dict with filename as key and patterns (including detailed findings) as value.
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
        patterns = {"_code": code, "detailed_findings": []}  # Store code and detailed findings

        # Define patterns for detailed extraction (similar to heuristics.py)
        check_patterns = {
            "ast": [
                {"key": "eval_usage", "pattern": r"eval\(", "description": "Use of eval()", "advice": "Avoid eval; use safer alternatives like ast.literal_eval."},
                {"key": "exec_usage", "pattern": r"exec\(", "description": "Use of exec()", "advice": "Avoid exec; restrict dynamic code execution."},
                {"key": "subprocess_usage", "pattern": r"subprocess\.(Popen|call|run)\(", "description": "Subprocess calls", "advice": "Validate subprocess arguments to prevent injection."},
                {"key": "os_system", "pattern": r"os\.system\(", "description": "os.system call", "advice": "Use subprocess with validated arguments instead."},
                {"key": "pickle_loads", "pattern": r"pickle\.loads\(", "description": "pickle.loads usage", "advice": "Use safer serialization formats like JSON."},
                {"key": "subprocess_shell_true", "pattern": r"subprocess\.(Popen|call|run)\([^)]*shell\s*=\s*True", "description": "Subprocess with shell=True", "advice": "Avoid shell=True; use shell=False with validated args."},
                {"key": "insecure_serialization", "pattern": r"(pickle|marshal|shelve)\.(loads|load)\(", "description": "Insecure serialization", "advice": "Use JSON or other safe formats."},
                {"key": "input_usage", "pattern": r"input\(", "description": "Use of input()", "advice": "Validate user input to prevent injection."},
                {"key": "dynamic_import", "pattern": r"__import__\(", "description": "Dynamic import (__import__)", "advice": "Validate module sources before importing."},
            ],
            "regex": [
                {"key": "ip_blocking", "pattern": r"if .*in.*blacklist", "description": "IP blocking pattern", "advice": "Review blacklist logic for potential abuse."},
                {"key": "spam_subscription", "pattern": r"subscribe.*mail", "description": "Spam subscription pattern", "advice": "Verify email subscription logic."},
                {"key": "dangerous_links", "pattern": r"http[s]?://.*(exe|bat|js|vbs|sh|dll)", "description": "Dangerous file links", "advice": "Avoid links to executable files."},
                {"key": "malicious_download", "pattern": r"requests\.get\s*\(.*\b(url|path)\b", "description": "Suspicious download", "advice": "Validate download sources."},
                {"key": "user_data_exfiltration", "pattern": r"open\s*\(.*\.(txt|csv|log)\)", "description": "Data exfiltration attempt", "advice": "Secure file operations."},
                {"key": "registry_access", "pattern": r"winreg", "description": "Windows registry access", "advice": "Verify necessity of registry operations."},
                {"key": "base64_decode_eval", "pattern": r"base64\.b64decode\s*\([^)]*\)\s*.*eval\s*\(", "description": "Base64 decode with eval", "advice": "Avoid decoding and executing dynamic code."},
                {"key": "suspicious_dynamic_exec", "pattern": r"(compile|exec)\s*\(", "description": "Dynamic execution pattern", "advice": "Restrict dynamic code execution."},
                {"key": "dangerous_imports", "pattern": r"(socket|ctypes|pickle|marshal|Crypto)", "description": "Dangerous imports", "advice": "Review use of socket, ctypes, etc."},
                {"key": "obfuscated_code", "pattern": r"\\x[0-9A-Fa-f]{2}", "description": "Obfuscated code", "advice": "Clarify code to avoid hiding malicious intent."},
                {"key": "suspicious_file_ops", "pattern": r"open\s*\(.*[wa]\)", "description": "Suspicious file operations", "advice": "Validate file write operations."},
                {"key": "dynamic_module_loading", "pattern": r"(importlib\.import_module|__import__)", "description": "Dynamic module loading", "advice": "Validate imported modules."},
                {"key": "suspicious_getattr", "pattern": r"getattr\s*\(.*['\"]", "description": "Suspicious getattr usage", "advice": "Ensure getattr is used safely."},
                {"key": "hardcoded_credentials", "pattern": r"(password|secret|api_key)\s*=\s*['\"][^'\"]+['\"]", "description": "Hardcoded credentials", "advice": "Store credentials in environment variables."},
                {"key": "insecure_protocol", "pattern": r"http://", "description": "Use of HTTP", "advice": "Use HTTPS for secure communication."},
                {"key": "sql_injection", "pattern": r"execute\s*\(.*%.*\)", "description": "Potential SQL injection", "advice": "Use parameterized queries."},
                {"key": "reverse_shell", "pattern": r"socket\.(socket|create_connection)\s*\(", "description": "Reverse shell pattern", "advice": "Remove or secure network connections."},
                {"key": "weak_encryption", "pattern": r"cryptography\.(md5|sha1)", "description": "Weak encryption (MD5/SHA1)", "advice": "Use stronger algorithms like SHA-256."},
                {"key": "malicious_comments", "pattern": r"(backdoor|malware|exploit|keylogger|ransom)", "description": "Malicious comments", "advice": "Remove suspicious comments."},
                {"key": "hidden_process", "pattern": r"CREATE_NO_WINDOW|SW_HIDE", "description": "Hidden process creation", "advice": "Avoid hiding processes."},
                {"key": "camera_access", "pattern": r"cv2\.VideoCapture|pygame\.camera", "description": "Camera access", "advice": "Verify necessity and user consent."},
                {"key": "microphone_access", "pattern": r"sounddevice\.rec|pyaudio\.PyAudio", "description": "Microphone access", "advice": "Verify necessity and user consent."},
                {"key": "dropper_code", "pattern": r"requests\.get\(.*\)\.content.*exec\(|urllib\.request\.urlopen\(.*\)\.read\(\)", "description": "Dropper code pattern", "advice": "Remove or secure dynamic code execution."},
                {"key": "code_injection", "pattern": r"ctypes\.windll|WriteProcessMemory", "description": "Code injection attempt", "advice": "Secure memory operations."},
                {"key": "file_permission_changes", "pattern": r"os\.chmod|os\.chown", "description": "File permission changes", "advice": "Validate permission modifications."},
                {"key": "in_memory_execution", "pattern": r"exec\(compile\(|eval\(compile\(|exec\(.*decode\(['\"]base64", "description": "In-memory code execution", "advice": "Avoid executing decoded code."},
                {"key": "env_variable_usage", "pattern": r"os\.getenv|os\.environ\.get", "description": "Environment variable access", "advice": "Validate variable usage."},
            ],
            "bandit": [
                {"key": "assert_used", "pattern": r"\bassert\b", "description": "Use of assert", "advice": "Avoid assert in production code."},
                {"key": "exec_used", "pattern": r"exec\(", "description": "Use of exec", "advice": "Restrict dynamic code execution."},
                {"key": "bad_file_perms", "pattern": r"os\.chmod\s*\(.*0o?777|0o?666", "description": "Insecure file permissions", "advice": "Use restrictive permissions (e.g., 600)."},
                {"key": "bind_all_interfaces", "pattern": r"\.bind\s*\(\s*['\"](0\.0\.0\.0|::)['\"]\s*\)", "description": "Binding to all interfaces", "advice": "Bind to specific interfaces."},
                {"key": "hardcoded_password", "pattern": r"(password|passwd|pwd|secret|token)\s*=\s*['\"][^'\"]+['\"]", "description": "Hardcoded password", "advice": "Use environment variables."},
                {"key": "hardcoded_tmp", "pattern": r"(/tmp|/var/tmp|C:\\TEMP)(\\\\|/)[^'\"]+", "description": "Hardcoded temporary directory", "advice": "Use tempfile module."},
                {"key": "hardcoded_ssl_cert", "pattern": r"context\.load_cert_chain\(['\"]", "description": "Hardcoded SSL certificate", "advice": "Store certificates securely."},
                {"key": "aws_keys", "pattern": r"(AKIA|ASIA)[A-Z0-9]{16}", "description": "Hardcoded AWS keys", "advice": "Use AWS Secrets Manager."},
                {"key": "pickle_used", "pattern": r"import\s+pickle", "description": "Use of pickle", "advice": "Use JSON or other safe formats."},
                {"key": "marshal_used", "pattern": r"marshal\.loads\(", "description": "Use of marshal", "advice": "Avoid marshal for serialization."},
                {"key": "md5_used", "pattern": r"hashlib\.md5\(", "description": "Use of MD5", "advice": "Use SHA-256 or stronger algorithms."},
                {"key": "cgi_used", "pattern": r"import\s+cgi", "description": "Use of cgi module", "advice": "Avoid cgi; use modern frameworks."},
                {"key": "ftplib_used", "pattern": r"import\s+ftplib", "description": "Use of ftplib", "advice": "Use secure alternatives like sftp."},
                {"key": "mktemp_used", "pattern": r"tempfile\.mktemp\(", "description": "Use of mktemp", "advice": "Use tempfile.TemporaryFile."},
                {"key": "eval_used", "pattern": r"eval\(", "description": "Use of eval", "advice": "Use safer alternatives."},
                {"key": "mark_safe_used", "pattern": r"mark_safe\(", "description": "Django mark_safe usage", "advice": "Validate input before marking safe."},
                {"key": "httpsconnection_used", "pattern": r"HTTPSConnection\s*\(", "description": "Insecure HTTPS connection", "advice": "Use modern TLS settings."},
                {"key": "urlopen_used", "pattern": r"urllib\.(request\.)?urlopen\s*\(", "description": "urllib.urlopen usage", "advice": "Use requests with timeout and validation."},
                {"key": "random_used", "pattern": r"import\s+random", "description": "Use of random module", "advice": "Use secrets module for cryptographic tasks."},
                {"key": "telnetlib_used", "pattern": r"import\s+telnetlib", "description": "Use of telnetlib", "advice": "Use SSH or secure protocols."},
                {"key": "cElementTree_used", "pattern": r"from\s+xml\.etree\s+import\s+cElementTree", "description": "Use of cElementTree", "advice": "Use defusedxml for XML parsing."},
                {"key": "paramiko_insecure", "pattern": r"\.set_missing_host_key_policy\(", "description": "Insecure Paramiko usage", "advice": "Set secure host key policies."},
                {"key": "ssl_bad_version", "pattern": r"PROTOCOL_(SSLv2|SSLv3|TLSv1|TLSv1\.1)\b", "description": "Insecure SSL/TLS version", "advice": "Use TLS 1.2 or higher."},
                {"key": "ssl_bad_defaults", "pattern": r"OP_NO_SSLv2|OP_NO_SSLv3", "description": "Insecure SSL defaults", "advice": "Configure secure SSL settings."},
                {"key": "paramiko_exec_command", "pattern": r"\.exec_command\s*\(", "description": "Paramiko exec_command", "advice": "Validate commands before execution."},
                {"key": "subprocess_shell_true", "pattern": r"subprocess\.(Popen|run|call)\(.*shell\s*=\s*True", "description": "Subprocess with shell=True", "advice": "Use shell=False with validated args."},
                {"key": "subprocess_without_shell", "pattern": r"subprocess\.(Popen|run|call)\(.*shell\s*=\s*False", "description": "Subprocess without shell", "advice": "Ensure proper argument validation."},
                {"key": "other_shell_true", "pattern": r"\b(shell|executable)\s*=\s*True", "description": "Other shell=True usage", "advice": "Avoid shell=True in custom functions."},
                {"key": "partial_path_process", "pattern": r"(Popen|run|call)\(['\"][^/\\][^'\"]+['\"]", "description": "Partial path in process", "advice": "Use full paths for executables."},
                {"key": "shell_process", "pattern": r"(Popen|run|call)\(.*, shell=True", "description": "Shell process execution", "advice": "Use subprocess with validation."},
                {"key": "hardcoded_sql", "pattern": r"(SELECT|INSERT|UPDATE|DELETE)\s+.*(FROM|INTO|SET|WHERE)", "description": "Hardcoded SQL queries", "advice": "Use parameterized queries."},
                {"key": "wildcard_injection", "pattern": r"(rm|ls|chmod|chown)\s+.*[\*\?\[\]]", "description": "Wildcard injection in commands", "advice": "Avoid wildcards in commands."},
                {"key": "django_extra_used", "pattern": r"\.extra\s*\(", "description": "Django extra() usage", "advice": "Use ORM methods instead."},
                {"key": "django_rawsql_used", "pattern": r"\.raw\s*\(|RawSQL\s*\(", "description": "Django raw SQL usage", "advice": "Use parameterized queries."},
                {"key": "logging_insecure", "pattern": r"logging\.basicConfig\(.*handlers\s*=\s*\[.*SocketHandler", "description": "Insecure logging config", "advice": "Avoid SocketHandler in logging."},
                {"key": "jinja2_autoescape_off", "pattern": r"Environment\s*\(.*autoescape\s*=\s*False", "description": "Jinja2 autoescape off", "advice": "Enable autoescape for security."},
            ],
            "yara": [
                {"key": "yara_match", "pattern": None, "description": "YARA rule match detected", "advice": "Review YARA rule details and code context."},
            ],
        }

        # AST-based checks
        if "ast" in check_types:
            try:
                tree = ast.parse(code)
                for check in check_patterns["ast"]:
                    key = check["key"]
                    patterns[key] = False
                    if key == "eval_usage":
                        patterns[key] = any(isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "eval" for node in ast.walk(tree))
                    elif key == "exec_usage":
                        patterns[key] = any(isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "exec" for node in ast.walk(tree))
                    elif key == "subprocess_usage":
                        patterns[key] = any(isinstance(node, ast.Call) and hasattr(node.func, 'attr') and node.func.attr in ["Popen", "call", "run"] for node in ast.walk(tree))
                    elif key == "os_system":
                        patterns[key] = any(isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" for node in ast.walk(tree))
                    elif key == "pickle_loads":
                        patterns[key] = any(isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle" for node in ast.walk(tree))
                    elif key == "subprocess_shell_true":
                        patterns[key] = any(isinstance(node, ast.Call) and hasattr(node.func, 'attr') and node.func.attr in ["Popen", "call", "run"] and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords) for node in ast.walk(tree))
                    elif key == "insecure_serialization":
                        patterns[key] = any(isinstance(node, ast.Call) and getattr(node.func, 'attr', None) in ["loads", "load"] and isinstance(node.func.value, ast.Name) and node.func.value.id in ["pickle", "marshal", "shelve"] for node in ast.walk(tree))
                    elif key == "input_usage":
                        patterns[key] = any(isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "input" for node in ast.walk(tree))
                    elif key == "dynamic_import":
                        patterns[key] = any(isinstance(node, ast.Call) and getattr(node.func, 'id', None) == "__import__" for node in ast.walk(tree))
                    if patterns[key]:
                        # Extract line numbers and snippets
                        for idx, line in enumerate(code.splitlines(), 1):
                            if re.search(check["pattern"], line, re.IGNORECASE):
                                patterns["detailed_findings"].append(
                                    f"Line {idx}: {line.strip()} [Type: AST] [Reason: {check['description']}] [Advice: {check['advice']}]"
                                )
            except Exception as e:
                print(f"AST parsing error in {filename}: {e}")

        # Regex-based checks
        if "regex" in check_types:
            for check in check_patterns["regex"]:
                key = check["key"]
                patterns[key] = bool(re.search(check["pattern"], code, re.IGNORECASE))
                if patterns[key]:
                    for idx, line in enumerate(code.splitlines(), 1):
                        if re.search(check["pattern"], line, re.IGNORECASE):
                            patterns["detailed_findings"].append(
                                f"Line {idx}: {line.strip()} [Type: Regex] [Reason: {check['description']}] [Advice: {check['advice']}]"
                            )

        # Bandit checks
        if "bandit" in check_types:
            bandit_vulns = detect_bandit_vulnerabilities(code)
            patterns.update(bandit_vulns)
            for check in check_patterns["bandit"]:
                key = check["key"]
                if patterns.get(key, False):
                    for idx, line in enumerate(code.splitlines(), 1):
                        if re.search(check["pattern"], line, re.IGNORECASE):
                            patterns["detailed_findings"].append(
                                f"Line {idx}: {line.strip()} [Type: Bandit] [Reason: {check['description']}] [Advice: {check['advice']}]"
                            )

        # YARA checks
        if "yara" in check_types and yara_rules:
            try:
                patterns["yara_match"] = bool(yara_rules.match(data=code))
                if patterns["yara_match"]:
                    patterns["detailed_findings"].append(
                        f"Line -: N/A [Type: YARA] [Reason: YARA rule match detected] [Advice: Review YARA rule details and code context.]"
                    )
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
    vulns['bad_file_perms'] = bool(re.search(r'os\.chmod\s*\(.*0o?777|0o?666', code))

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
    vulns['hardcoded_password'] = bool(re.search(r'(password|passwd|pwd|secret|token)\s*=\s*[\'"][^\'"]+[\'"]', code, re.IGNORECASE))

    # B106: hardcoded_tmp_directory
    vulns['hardcoded_tmp'] = bool(re.search(r'(/tmp|/var/tmp|C:\\TEMP)(\\\\|/)[^\'"]+', code, re.IGNORECASE))

    # B107: hardcoded_ssl_cert
    vulns['hardcoded_ssl_cert'] = bool(re.search(r'context\.load_cert_chain\([\'"]', code))

    # B108: hardcoded_aws_keys
    vulns['aws_keys'] = bool(re.search(r'(AKIA|ASIA)[A-Z0-9]{16}', code))

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
    vulns['httpsconnection_used'] = bool(re.search(r'HTTPSConnection\s*\(', code))

    # B310: urllib_urlopen
    vulns['urlopen_used'] = bool(re.search(r'urllib\.(request\.)?urlopen\s*\(', code))

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
    vulns['cElementTree_used'] = bool(re.search(r'from\s+xml\.etree\s+import\s+cElementTree', code))

    # B314: paramiko
    vulns['paramiko_insecure'] = any(
        isinstance(node, ast.Call) and
        getattr(node.func, 'attr', None) == 'set_missing_host_key_policy' and
        getattr(node.func.value, 'id', None) == 'client'
        for node in ast.walk(tree)
    )

    # B501: ssl_with_bad_version
    vulns['ssl_bad_version'] = bool(re.search(r'PROTOCOL_(SSLv2|SSLv3|TLSv1|TLSv1\.1)\b', code))

    # B502: ssl_with_bad_defaults
    vulns['ssl_bad_defaults'] = bool(re.search(r'OP_NO_SSLv2|OP_NO_SSLv3', code))

    # B601: paramiko_calls
    vulns['paramiko_exec_command'] = bool(re.search(r'\.exec_command\s*\(', code))

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
    vulns['subprocess_without_shell'] = bool(re.search(r'subprocess\.(Popen|run|call)\(.*shell\s*=\s*False', code))

    # B604: any_other_function_with_shell_equals_true
    vulns['other_shell_true'] = bool(re.search(r'\b(shell|executable)\s*=\s*True', code)) and not vulns.get('subprocess_shell_true', False)

    # B605: start_process_with_partial_path
    vulns['partial_path_process'] = bool(re.search(r'(Popen|run|call)\([\'"][^/\\][^\'"]+[\'"]', code))

    # B606: assert_used
    vulns['assert_used'] = vulns.get('assert_used', False) or bool(re.search(r'\bassert\b', code))

    # B607: start_process_with_a_shell
    vulns['shell_process'] = bool(re.search(r'(Popen|run|call)\(.*, shell=True', code))

    # B608: hardcoded_sql_expressions
    vulns['hardcoded_sql'] = bool(re.search(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*(FROM|INTO|SET|WHERE)', code, re.IGNORECASE | re.DOTALL))

    # B609: linux_commands_wildcard_injection
    vulns['wildcard_injection'] = bool(re.search(r'(rm|ls|chmod|chown)\s+.*[\*\?\[\]]', code))

    # B610: django_extra_used
    vulns['django_extra_used'] = bool(re.search(r'\.extra\s*\(', code))

    # B611: django_rawsql_used
    vulns['django_rawsql_used'] = bool(re.search(r'\.raw\s*\(|RawSQL\s*\(', code))

    # B612: logging_config_insecure_listen
    vulns['logging_insecure'] = bool(re.search(r'logging\.basicConfig\(.*handlers\s*=\s*\[.*SocketHandler', code))

    # B701: jinja2_autoescape_false
    vulns['jinja2_autoescape_off'] = bool(re.search(r'Environment\s*\(.*autoescape\s*=\s*False', code))

    return vulns

def score_maliciousness(results):
    """
    Scores the maliciousness of files based on detected patterns.
    Restored to original scoring logic from first response.
    """
    scores = {}
    for filename, patterns in results.items():
        score = 0
        # AST and regex patterns
        for pattern, value in patterns.items():
            if pattern == "eval_usage" and value:
                score += 10
            elif pattern == "exec_usage" and value:
                score += 15
            elif pattern == "subprocess_usage" and value:
                score += 8
            elif pattern == "os_system" and value:
                score += 12
            elif pattern == "pickle_loads" and value:
                score += 10
            elif pattern == "subprocess_shell_true" and value:
                score += 15
            elif pattern == "insecure_serialization" and value:
                score += 10
            elif pattern == "input_usage" and value:
                score += 5
            elif pattern == "dynamic_import" and value:
                score += 8
            elif pattern == "yara_match" and value:
                score += 20
            elif pattern == "ip_blocking" and value:
                score += 5
            elif pattern == "spam_subscription" and value:
                score += 5
            elif pattern == "dangerous_links" and value:
                score += 10
            elif pattern == "malicious_download" and value:
                score += 15
            elif pattern == "user_data_exfiltration" and value:
                score += 12
            elif pattern == "registry_access" and value:
                score += 10
            elif pattern == "base64_decode_eval" and value:
                score += 18
            elif pattern == "suspicious_dynamic_exec" and value:
                score += 15
            elif pattern == "dangerous_imports" and value:
                score += 8
            elif pattern == "obfuscated_code" and value:
                score += 10
            elif pattern == "suspicious_file_ops" and value:
                score += 8
            elif pattern == "dynamic_module_loading" and value:
                score += 10
            elif pattern == "suspicious_getattr" and value:
                score += 8
            elif pattern == "hardcoded_credentials" and value:
                score += 15
            elif pattern == "insecure_protocol" and value:
                score += 8
            elif pattern == "sql_injection" and value:
                score += 12
            elif pattern == "reverse_shell" and value:
                score += 20
            elif pattern == "weak_encryption" and value:
                score += 10
            elif pattern == "malicious_comments" and value:
                score += 5
            elif pattern == "hidden_process" and value:
                score += 15
            elif pattern == "camera_access" and value:
                score += 12
            elif pattern == "microphone_access" and value:
                score += 12
            elif pattern == "dropper_code" and value:
                score += 18
            elif pattern == "code_injection" and value:
                score += 20
            elif pattern == "file_permission_changes" and value:
                score += 10
            elif pattern == "in_memory_execution" and value:
                score += 15
            elif pattern == "env_variable_usage" and value:
                score += 5
            # Bandit patterns
            elif pattern in [
                'assert_used', 'exec_used', 'bad_file_perms', 'bind_all_interfaces',
                'hardcoded_password', 'hardcoded_tmp', 'hardcoded_ssl_cert', 'aws_keys',
                'pickle_used', 'marshal_used', 'md5_used', 'cgi_used', 'ftplib_used',
                'mktemp_used', 'eval_used', 'mark_safe_used', 'httpsconnection_used',
                'urlopen_used', 'random_used', 'telnetlib_used', 'cElementTree_used',
                'paramiko_insecure', 'ssl_bad_version', 'ssl_bad_defaults',
                'paramiko_exec_command', 'subprocess_shell_true', 'subprocess_without_shell',
                'other_shell_true', 'partial_path_process', 'shell_process',
                'hardcoded_sql', 'wildcard_injection', 'django_extra_used',
                'django_rawsql_used', 'logging_insecure', 'jinja2_autoescape_off'
            ] and value:
                score += 10  # Generic score for Bandit issues
        # Heuristic patterns
        for heuristic_pattern in ['ml_suspicion', 'api_keys', 'encryption', 'network', 'hardware', 'shell_injection', 'sql_injection']:
            if heuristic_pattern in patterns:
                if heuristic_pattern == 'ml_suspicion':
                    score += int(patterns[heuristic_pattern] * 0.1)  # Scale ML suspicion
                else:
                    for key, value in patterns[heuristic_pattern].items():
                        if key == 'found' and value:
                            score += 10
        # Plugin results
        for key in patterns:
            if key.startswith("plugin_") and isinstance(patterns[key], (int, float)):
                score += min(int(patterns[key] * 2), 20)
        scores[filename] = min(score, 100)  # Cap at 100
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