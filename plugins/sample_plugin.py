def check(filename, code):
    """
    ������ �������: ��������� ������� ����� 'TODO' � ����.
    ���� ����������, ���������� �������������� ���������� � ����� �� ���������.
    """
    result = {}
    if "TODO" in code:
        result["plugin_todo_found"] = "���������� ����� TODO. �����: �������� TODO �� ���������� ������ ��� ������� �."
    else:
        result["plugin_todo_found"] = "TODO �� ������."
    return result
