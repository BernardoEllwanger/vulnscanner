"""Wrapper para Gitleaks — detector de segredos em repositórios."""

import json
import os
from tools.base import BaseExternalTool


class GitleaksTool(BaseExternalTool):
    name = "Gitleaks"
    tool_id = "gitleaks"
    binary_name = "gitleaks"
    description = "Detector de segredos em repositórios"
    category = "secret_scanner"
    default_timeout = 60

    def build_command(self, target_url, **kwargs):
        source_path = kwargs.get("source_path", ".")
        self._output_file = self._get_temp_path(suffix=".json")
        return [
            "gitleaks", "detect",
            "--source", source_path,
            "--report-format", "json",
            "--report-path", self._output_file,
            "--no-git",
            "--exit-code", "0",
        ]

    def parse_output(self, stdout, stderr, **kwargs):
        findings = []

        output_file = getattr(self, "_output_file", None)
        raw = ""
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, encoding="utf-8") as f:
                    raw = f.read()
            except Exception:
                pass
            finally:
                try:
                    os.remove(output_file)
                except Exception:
                    pass

        if not raw or not raw.strip():
            return findings

        try:
            items = json.loads(raw)
            if not isinstance(items, list):
                items = [items]

            for item in items:
                if not isinstance(item, dict):
                    continue
                file_path = item.get("File", "")
                if file_path and not os.path.isabs(file_path):
                    file_path = os.path.abspath(file_path)
                findings.append({
                    "severity": "ALTO",
                    "category": f"Gitleaks: {item.get('RuleID', 'Secret')}",
                    "details": {
                        "arquivo": file_path,
                        "linha": item.get("StartLine", ""),
                        "regra": item.get("RuleID", ""),
                        "detalhe": item.get("Description", "Segredo detectado no código fonte"),
                    },
                })
        except json.JSONDecodeError:
            pass

        return findings
