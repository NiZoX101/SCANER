import re

def ml_analyze(code):
    """
    Простейшая эвристика для оценки подозрительности кода.
    Возвращает число от 0 до 100.
    """
    suspicious_terms = ["eval(", "exec(", "__import__", "compile(", "pickle.loads", "base64.b64decode"]
    count = sum(code.count(term) for term in suspicious_terms)
    hex_matches = re.findall(r'\\x[0-9A-Fa-f]{2}', code)
    obf_score = len(hex_matches)
    score = (count * 10 + obf_score) / (len(code) / 1000 + 1)
    return int(min(score, 100))

def detailed_extract_suspicious_lines(code):
    """
    Извлекает строки с подозрительными конструкциями.
    Возвращает список строк с номером, описанием и рекомендациями.
    """
    patterns = [
        {"pattern": r"eval\(", "description": "Динамическое выполнение кода", "advice": "Избегайте использования eval; применяйте безопасные альтернативы."},
        {"pattern": r"exec\(", "description": "Динамическое выполнение кода", "advice": "Избегайте использования exec или ограничьте область применения."},
        {"pattern": r"__import__", "description": "Динамическая загрузка модулей", "advice": "Проверяйте источники модулей и избегайте лишнего динамического импорта."},
        {"pattern": r"compile\(", "description": "Компиляция кода во время выполнения", "advice": "Проверьте исходный код перед компиляцией."},
        {"pattern": r"pickle\.loads", "description": "Десериализация без проверки", "advice": "Используйте безопасные форматы, например, JSON."},
        {"pattern": r"base64\.b64decode", "description": "Декодирование Base64, возможная обфускация", "advice": "Проверьте контекст декодирования."},
        {"pattern": r"socket\.socket\(", "description": "Создание сетевого сокета", "advice": "Проверьте методы подключения и валидацию данных."},
        {"pattern": r"os\.system\(", "description": "Вызов системных команд", "advice": "Используйте subprocess с валидированными аргументами."},
        {"pattern": r"subprocess\.", "description": "Запуск внешних процессов", "advice": "Валидация входных данных обязательна."},
        {"pattern": r"importlib\.import_module", "description": "Динамический импорт модулей", "advice": "Убедитесь, что импортируемый модуль безопасен."},
        {"pattern": r"winreg", "description": "Доступ к реестру Windows", "advice": "Проверьте необходимость доступа и безопасность операций."},
        {"pattern": r"(AES\.new|Fernet\()", "description": "Использование криптографии", "advice": "Убедитесь в корректной настройке ключей и режимов."},
        {"pattern": r"\b(password|secret|key)\b", "description": "Хардкоденные пароли/секреты", "advice": "Храните данные в переменных окружения или безопасном хранилище."}
    ]
    detailed_lines = []
    for idx, line in enumerate(code.splitlines(), 1):
        for entry in patterns:
            if re.search(entry["pattern"], line):
                detailed_lines.append(
                    f"Line {idx}: {line.strip()} [Причина: {entry['description']}] [Совет: {entry['advice']}]"
                )
    return detailed_lines

def check_api_keys(code):
    """
    Проверяет код на наличие API-ключей.
    Возвращает подробный словарь с результатами.
    """
    patterns = {
        "aws_key": {"pattern": r"AKIA[0-9A-Z]{16}", "description": "AWS ключ", "advice": "Используйте переменные окружения."},
        "discord_token": {"pattern": r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}", "description": "Discord токен", "advice": "Храните в защищённом хранилище."},
        "telegram_bot": {"pattern": r"\d{9,10}:[a-zA-Z0-9_-]{35}", "description": "Telegram-бот токен", "advice": "Храните вне исходного кода."}
    }
    findings = {}
    for key, info in patterns.items():
        match = re.search(info["pattern"], code)
        if match:
            findings[key] = {"found": True, "description": info["description"], "advice": info["advice"], "match": match.group(0)}
        else:
            findings[key] = {"found": False}
    return findings

def check_encryption_usage(code):
    """
    Детектирует использование криптографии (AES, Fernet, XOR).
    """
    findings = {
        "aes_usage": {"found": bool(re.search(r"AES\.new\(", code)), "description": "AES шифрование", "advice": "Проверьте корректность ключей."},
        "fernet_usage": {"found": bool(re.search(r"Fernet\(", code)), "description": "Fernet шифрование", "advice": "Проверьте настройки токена."},
        "xor_usage": {"found": bool(re.search(r"\bXOR\b", code, re.IGNORECASE)), "description": "Возможная XOR обфускация", "advice": "Пересмотрите алгоритм обфускации."}
    }
    return findings

def check_socket_and_server(code):
    """
    Проверяет создание сетевых сокетов и серверов.
    """
    findings = {
        "socket_creation": {"found": bool(re.search(r"socket\.socket\(", code)), "description": "Создание сокета", "advice": "Проверьте безопасность соединения."},
        "server_creation": {"found": bool(re.search(r"(bind|listen)\s*\(", code)), "description": "Прослушивание порта", "advice": "Убедитесь в защите серверных процессов."}
    }
    return findings

def check_hardware_access(code):
    """
    Проверяет доступ к камере, микрофону, GPS и файловым операциям.
    """
    findings = {
        "camera_access": {"found": bool(re.search(r"(cv2\.VideoCapture|picamera\.PiCamera)", code)), "description": "Доступ к камере", "advice": "Проверьте необходимость и защиту доступа."},
        "microphone_access": {"found": bool(re.search(r"(pyaudio\.PyAudio)", code)), "description": "Доступ к микрофону", "advice": "Проверьте, что запись звука разрешена."},
        "gps_access": {"found": bool(re.search(r"(gps\.gps|geopy\.Nominatim)", code)), "description": "Доступ к GPS/геолокации", "advice": "Обеспечьте защиту геоданных."},
        "filesystem_ops": {"found": bool(re.search(r"(open\(|os\.remove\(|shutil\.rmtree\()", code)), "description": "Операции с файловой системой", "advice": "Проверьте безопасность работы с файлами."}
    }
    return findings

def check_shell_injection(code):
    """
    Дополнительная проверка: использование subprocess с shell=True.
    """
    found = bool(re.search(r"subprocess\.run\([^)]*shell\s*=\s*True", code))
    return {"shell_injection": {"found": found, "description": "Использование shell=True", "advice": "Избегайте shell=True или валидируйте аргументы."}}

def check_sql_injection(code):
    """
    Проверяет наличие незащищённых SQL-запросов.
    """
    found = bool(re.search(r"(?i)select\s+.*from\s+.*", code))
    return {"sql_injection": {"found": found, "description": "SQL-запросы без параметризации", "advice": "Используйте параметризованные запросы."}}

def perform_heuristics(filename, code, plugin_runner):
    """
    Объединяет все проверки: базовые, дополнительные (shell, SQL) и плагины.
    """
    results = {}
    results["ml_suspicion"] = ml_analyze(code)
    results["detailed_lines"] = detailed_extract_suspicious_lines(code)
    results["api_keys"] = check_api_keys(code)
    results["encryption"] = check_encryption_usage(code)
    results["network"] = check_socket_and_server(code)
    results["hardware"] = check_hardware_access(code)
    # Дополнительные проверки
    results.update(check_shell_injection(code))
    results.update(check_sql_injection(code))
    # Выполнение плагинов
    plugin_results = plugin_runner(filename, code)
    results.update(plugin_results)
    return results
