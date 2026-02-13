"""Wrapper para SQLMap — ferramenta de SQL Injection."""

import json
import os
import re
from tools.base import BaseExternalTool


class SqlmapTool(BaseExternalTool):
    name = "SQLMap"
    tool_id = "sqlmap"
    binary_name = "sqlmap"
    description = "Ferramenta de detecção de SQL Injection"
    category = "sqli"
    default_timeout = 300

    def build_command(self, target_url, **kwargs):
        output_dir = self._get_temp_path(suffix="")
        # Remover o arquivo temp, sqlmap precisa de um diretório
        if os.path.exists(output_dir):
            os.remove(output_dir)
        self._output_dir = output_dir
        return [
            "sqlmap", "-u", target_url,
            "--batch", "--forms", "--crawl=2",
            "--output-dir", output_dir,
            "--risk=1", "--level=1",
        ]

    def parse_output(self, stdout, stderr, **kwargs):
        findings = []
        output = stdout or ""

        # Parsear stdout por indicadores de vulnerabilidade
        vuln_patterns = [
            (r"Parameter:\s*(.+?)\s+.*?is vulnerable", "CRÍTICO"),
            (r"(\w+)\s+parameter\s+'([^']+)'\s+is vulnerable", "CRÍTICO"),
            (r"Type:\s*(.+)", None),
        ]

        for line in output.splitlines():
            line = line.strip()
            if "is vulnerable" in line.lower():
                findings.append({
                    "severity": "CRÍTICO",
                    "category": "SQLMap: SQL Injection Confirmado",
                    "details": {
                        "detalhe": line,
                    },
                })
            elif "might be injectable" in line.lower():
                findings.append({
                    "severity": "ALTO",
                    "category": "SQLMap: Possível SQL Injection",
                    "details": {
                        "detalhe": line,
                    },
                })

        # Tentar parsear logs do diretório de output
        try:
            if hasattr(self, "_output_dir") and os.path.isdir(self._output_dir):
                for root, dirs, files in os.walk(self._output_dir):
                    for fname in files:
                        if fname == "log":
                            fpath = os.path.join(root, fname)
                            with open(fpath, encoding="utf-8", errors="ignore") as f:
                                log_text = f.read()
                            for m in re.finditer(r"Parameter:\s*(.+)", log_text):
                                param_info = m.group(1).strip()
                                if param_info and not any(param_info in f.get("details", {}).get("detalhe", "") for f in findings):
                                    findings.append({
                                        "severity": "ALTO",
                                        "category": "SQLMap: Parâmetro Injetável",
                                        "details": {"detalhe": param_info},
                                    })
        except Exception:
            pass

        return findings
