def check(filename, code):
    """
    Пример плагина: проверяет наличие метки 'TODO' в коде.
    Если обнаружено, возвращает дополнительную информацию и совет по обработке.
    """
    result = {}
    if "TODO" in code:
        result["plugin_todo_found"] = "Обнаружена метка TODO. Совет: замените TODO на конкретную задачу или удалите её."
    else:
        result["plugin_todo_found"] = "TODO не найден."
    return result
