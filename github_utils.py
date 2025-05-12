from urllib.parse import urlparse
from github import Github
import os

def get_repository_files(repo_url, token=None):
    """
    Получает все файлы .py из указанного репозитория GitHub.
    """
    parsed_url = urlparse(repo_url)
    path_parts = parsed_url.path.strip("/").split("/")
    if len(path_parts) < 2:
        raise ValueError("Invalid repository URL.")
    
    owner, repo_name = path_parts[:2]
    
    g = Github(token) if token else Github()
    repo = g.get_repo(f"{owner}/{repo_name}")
    files = []
    
    contents = repo.get_contents("")
    while contents:
        file_content = contents.pop(0)
        if file_content.type == "file" and file_content.name.endswith(".py"):
            try:
                code = file_content.decoded_content.decode("utf-8", errors="replace")
                files.append((file_content.path, code))
            except Exception as e:
                print(f"Error decoding {file_content.path}: {e}")
        elif file_content.type == "dir":
            contents.extend(repo.get_contents(file_content.path))
    
    return files

def get_remote_files(url, token):
    return 

def get_local_files(path):
    files = []
    for root, _, filenames in os.walk(path):
        for fn in filenames:
            if fn.endswith(".py"):
                with open(os.path.join(root, fn), "r", errors="replace") as f:
                    files.append((os.path.relpath(f.name, path), f.read()))
    return files

def get_files(source, token=None):
    if source.startswith("http"):
        return get_remote_files(source, token)
    else:
        return get_local_files(source)