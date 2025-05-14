rule yr_MaliciousCode_1 { meta: description = "Detects potential malicious code execution" author = "Yara-Rules" date = "2023-01-15" strings: $a = "exec(" $b = "system(" condition: filename matches /.py$/ and any of ($a, $b) }

rule yr_MaliciousCode_2 { meta: description = "Detects eval usage" author = "Yara-Rules" date = "2023-02-10" strings: $a = "eval(" condition: filename matches /.py$/ and $a }

rule yr_SQLInjection_1 { meta: description = "Detects SQL injection via string concatenation" author = "Yara-Rules" date = "2023-03-05" strings: $a = "execute(" nocase $b = "+" fullword $c = "SELECT" nocase condition: filename matches /.py$/ and all of ($a, $b, $c) }

rule yr_SQLInjection_2 { meta: description = "Detects SQL injection with format strings" author = "Yara-Rules" date = "2023-03-15" strings: $a = "cursor.execute(" nocase $b = "%s" fullword condition: filename matches /.py$/ and all of ($a, $b) }

rule yr_XSS_1 { meta: description = "Detects potential XSS via script tags" author = "Yara-Rules" date = "2023-04-20" strings: $a = "<script" nocase $b = "document.write(" condition: filename matches /.py$/ and any of ($a, $b) }

rule yr_XSS_2 { meta: description = "Detects XSS via innerHTML" author = "Yara-Rules" date = "2023-05-01" strings: $a = ".innerHTML=" condition: filename matches /.py$/ and $a }

rule yr_CommandInjection_1 { meta: description = "Detects command injection via os.system" author = "Yara-Rules" date = "2023-06-10" strings: $a = "os.system(" $b = "|" condition: filename matches /.py$/ and all of ($a, $b) }

rule yr_CommandInjection_2 { meta: description = "Detects command injection via subprocess" author = "Yara-Rules" date = "2023-06-20" strings: $a = "subprocess.run(" $b = "shell=True" condition: filename matches /.py$/ and all of ($a, $b) }

rule yr_HardcodedSecrets_1 { meta: description = "Detects hardcoded passwords" author = "Yara-Rules" date = "2023-07-15" strings: $a = "password" nocase $b = "passwd" nocase condition: filename matches /.py$/ and any of ($a, $b) and not (filename matches /secrets.py$/) }

rule yr_HardcodedSecrets_2 { meta: description = "Detects API keys or tokens" author = "Yara-Rules" date = "2023-08-01" strings: $a = "api_key" nocase $b = "token" nocase $c = /[a-fA-F0-9]{32,}/ condition: filename matches /.py$/ and any of ($a, $b, $c) and not (filename matches /tokens.py$/) }

rule yr_InsecureHTTP_1 { meta: description = "Detects HTTP usage instead of HTTPS" author = "Yara-Rules" date = "2023-09-10" strings: $a = "http://" nocase $b = "requests.get(" condition: filename matches /.py$/ and $a and $b and not $a contains "https" }

rule yr_InsecureHTTP_2 { meta: description = "Detects insecure POST requests" author = "Yara-Rules" date = "2023-09-20" strings: $a = "requests.post(" $b = "http://" condition: filename matches /.py$/ and $a and $b and not $b contains "https" }

rule yr_WeakCrypto_1 { meta: description = "Detects weak MD5 usage" author = "Yara-Rules" date = "2023-10-05" strings: $a = "hashlib.md5(" condition: filename matches /.py$/ and $a }

rule yr_WeakCrypto_2 { meta: description = "Detects weak SHA1 usage" author = "Yara-Rules" date = "2023-10-15" strings: $a = "hashlib.sha1(" condition: filename matches /.py$/ and $a }

rule rl_Malware_1 { meta: description = "Detects potential malware loader" author = "ReversingLabs" date = "2022-11-10" strings: $a = "load_library(" $b = "create_process(" condition: filename matches /.py$/ and any of ($a, $b) }

rule rl_Malware_2 { meta: description = "Detects obfuscated code" author = "ReversingLabs" date = "2022-12-01" strings: $a = "exec(import(" condition: filename matches /.py$/ and $a }

rule rl_Exploit_1 { meta: description = "Detects exploit code" author = "ReversingLabs" date = "2023-01-15" strings: $a = "buffer_overflow(" $b = "shellcode" condition: filename matches /.py$/ and any of ($a, $b) }

rule rl_Exploit_2 { meta: description = "Detects remote code execution" author = "ReversingLabs" date = "2023-02-20" strings: $a = "remote_exec(" $b = "popen(" condition: filename matches /.py$/ and any of ($a, $b) }

rule yr_PathTraversal_1 { meta: description = "Detects path traversal with ../" author = "Yara-Rules" date = "2023-11-10" strings: $a = "../" $b = "open(" condition: filename matches /.py$/ and all of ($a, $b) }

rule yr_PathTraversal_2 { meta: description = "Detects access to /etc/" author = "Yara-Rules" date = "2023-11-20" strings: $a = "/etc/" condition: filename matches /.py$/ and $a }

rule yr_BufferOverflow_1 { meta: description = "Detects potential buffer overflow" author = "Yara-Rules" date = "2023-12-05" strings: $a = "strcpy(" $b = "memcpy(" condition: filename matches /.py$/ and any of ($a, $b) }

rule yr_UnvalidatedInput_1 { meta: description = "Detects unvalidated input" author = "Yara-Rules" date = "2024-01-10" strings: $a = "input(" $b = "eval(" condition: filename matches /.py$/ and all of ($a, $b) }

rule yr_UnvalidatedInput_2 { meta: description = "Detects unvalidated raw_input" author = "Yara-Rules" date = "2024-01-20" strings: $a = "raw_input(" condition: filename matches /.py$/ and $a }

rule yr_InsecureDependency_1 { meta: description = "Detects outdated requests library" author = "Yara-Rules" date = "2024-02-15" strings: $a = "requests==1." $b = "pip install" condition: filename matches /.py$/ and all of ($a, $b) }

rule yr_InsecureDependency_2 { meta: description = "Detects urllib usage" author = "Yara-Rules" date = "2024-02-25" strings: $a = "import urllib" condition: filename matches /.py$/ and $a and not (filename matches /legacy/) }

rule rl_Ransomware_1 { meta: description = "Detects ransomware behavior" author = "ReversingLabs" date = "2022-12-15" strings: $a = "encrypt_file(" $b = "ransom_note" condition: filename matches /.py$/ and any of ($a, $b) }

rule rl_Ransomware_2 { meta: description = "Detects file locking" author = "ReversingLabs" date = "2023-01-05" strings: $a = "fcntl.lockf(" condition: filename matches /.py$/ and $a }