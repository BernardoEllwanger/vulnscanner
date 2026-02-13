"""Wrapper para TruffleHog — scanner de segredos."""

import json
import os
from tools.base import BaseExternalTool


class TrufflehogTool(BaseExternalTool):
    name = "TruffleHog"
    tool_id = "trufflehog"
    binary_name = "trufflehog"
    description = "Scanner de segredos e credenciais"
    category = "secret_scanner"
    default_timeout = 60

    def build_command(self, target_url, **kwargs):
        source_path = kwargs.get("source_path", ".")
        return ["trufflehog", "filesystem", source_path, "--json", "--no-update"]

    def parse_output(self, stdout, stderr, **kwargs):
        findings = []
        for line in (stdout or "").strip().splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                source = item.get("SourceMetadata", {}).get("Data", {})
                file_info = source.get("Filesystem", {})

                detector = item.get("DetectorType", "Unknown")
                verified = item.get("Verified", False)
                sev = "CRÍTICO" if verified else "ALTO"

                file_path = file_info.get("file", "")
                if file_path and not os.path.isabs(file_path):
                    file_path = os.path.abspath(file_path)

                findings.append({
                    "severity": sev,
                    "category": f"TruffleHog: {detector}",
                    "details": {
                        "arquivo": file_path,
                        "linha": file_info.get("line", ""),
                        "detector": detector,
                        "verificado": "Sim" if verified else "Não",
                        "detalhe": f"Segredo do tipo '{detector}' {'verificado' if verified else 'detectado'}",
                    },
                })
            except json.JSONDecodeError:
                continue
        return findings
