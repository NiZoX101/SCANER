import os
import importlib.util

def run_plugins(filename, code):
    """
    Динамически загружает проверки из папки 'plugins'.
    Каждый плагин должен содержать функцию check(filename, code),
    возвращающую словарь с дополнительными флагами, подробными описаниями и советами.
    """
    plugin_results = {}
    plugins_dir = "./plugins"
    if os.path.isdir(plugins_dir):
        for plugin_file in os.listdir(plugins_dir):
            if plugin_file.endswith(".py"):
                plugin_path = os.path.join(plugins_dir, plugin_file)
                try:
                    spec = importlib.util.spec_from_file_location("plugin_module", plugin_path)
                    plugin_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(plugin_module)
                    if hasattr(plugin_module, "check"):
                        result = plugin_module.check(filename, code)
                        plugin_results.update(result)
                except Exception as e:
                    print(f"Error loading plugin {plugin_file}: {e}")
    return plugin_results
