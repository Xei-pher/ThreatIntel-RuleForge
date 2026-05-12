from typing import Dict, List

KEYWORD_MAP = [
    ("powershell", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("cmd.exe", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    ("scheduled task", "T1053.005", "Scheduled Task/Job: Scheduled Task"),
    ("registry run", "T1060", "Registry Run Keys / Startup Folder"),
    ("rundll32", "T1218.011", "System Binary Proxy Execution: Rundll32"),
    ("mshta", "T1218.005", "System Binary Proxy Execution: Mshta"),
    ("phishing", "T1566", "Phishing"),
    ("credential", "T1003", "OS Credential Dumping"),
    ("mimikatz", "T1003.001", "OS Credential Dumping: LSASS Memory"),
    ("c2", "T1071", "Application Layer Protocol"),
    ("command and control", "T1071", "Application Layer Protocol"),
    ("exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ("ransomware", "T1486", "Data Encrypted for Impact"),
    ("wmi", "T1047", "Windows Management Instrumentation"),
    ("service creation", "T1543.003", "Create or Modify System Process: Windows Service"),
]


def map_mitre(text: str) -> List[Dict]:
    lower = text.lower()
    mappings = []
    seen = set()
    for keyword, tid, name in KEYWORD_MAP:
        if keyword in lower and tid not in seen:
            seen.add(tid)
            idx = lower.find(keyword)
            evidence = text[max(0, idx - 120): idx + 180].replace("\n", " ").strip()
            mappings.append({
                "technique_id": tid,
                "technique_name": name,
                "evidence": evidence,
                "confidence": "medium",
            })
    return mappings
