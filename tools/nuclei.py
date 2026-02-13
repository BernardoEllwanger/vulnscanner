"""Wrapper para Nuclei — scanner de vulnerabilidades baseado em templates."""

import json
import re
from tools.base import BaseExternalTool


class NucleiTool(BaseExternalTool):
    name = "Nuclei"
    tool_id = "nuclei"
    binary_name = "nuclei"
    description = "Scanner de vulnerabilidades baseado em templates"
    category = "vuln_scanner"
    default_timeout = 120

    def get_version(self) -> str:
        ver = super().get_version()
        match = re.search(r"v[\d.]+", ver)
        return match.group(0) if match else ver

    def build_command(self, target_url, **kwargs):
        return ["nuclei", "-u", target_url, "-jsonl", "-silent"]

    def parse_output(self, stdout, stderr, **kwargs):
        findings = []
        for line in (stdout or "").strip().splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                info = item.get("info", {})
                findings.append({
                    "severity": self._map_severity(info.get("severity", "info")),
                    "category": f"Nuclei: {info.get('name', 'Unknown')}",
                    "details": {
                        "url": item.get("matched-at", item.get("host", "")),
                        "template": item.get("template-id", ""),
                        "description": info.get("description", ""),
                        "detalhe": f"Detectado pelo template '{item.get('template-id', '')}'",
                    },
                })
            except json.JSONDecodeError:
                continue
        return findings
