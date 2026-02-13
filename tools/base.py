"""Classe base para wrappers de ferramentas externas de segurança."""

import os
import re
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod


class BaseExternalTool(ABC):
    name: str = ""
    tool_id: str = ""
    binary_name: str = ""
    description: str = ""
    category: str = ""
    default_timeout: int = 120

    def __init__(self, log_callback=None):
        self._log = log_callback or (lambda msg, level="info": None)

    def is_installed(self) -> bool:
        return shutil.which(self.binary_name) is not None

    def get_version(self) -> str:
        if not self.is_installed():
            return ""
        try:
            result = subprocess.run(
                [self.binary_name, "--version"],
                capture_output=True, text=True, timeout=10,
                stdin=subprocess.DEVNULL,
            )
            out = (result.stdout or result.stderr or "").strip()
            line = out.splitlines()[0] if out else "unknown"
            return re.sub(r"\x1b\[[0-9;]*m", "", line)
        except Exception:
            return "unknown"

    def _get_temp_path(self, suffix=".json"):
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=f"vulnscan_{self.tool_id}_")
        os.close(fd)
        return path

    @abstractmethod
    def build_command(self, target_url: str, **kwargs) -> list:
        ...

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, **kwargs) -> list:
        """Retorna lista de dicts: {severity, category, details}"""
        ...

    def _map_severity(self, tool_severity: str) -> str:
        mapping = {
            "critical": "CRÍTICO", "high": "ALTO", "medium": "MÉDIO",
            "low": "BAIXO", "info": "INFO", "informational": "INFO",
        }
        return mapping.get(tool_severity.lower(), "INFO")

    def run(self, target_url: str, timeout: int = None, **kwargs) -> list:
        if not self.is_installed():
            self._log(f"[!] {self.name} não instalado, pulando.", "warning")
            return []

        timeout = timeout or self.default_timeout
        cmd = self.build_command(target_url, **kwargs)
        self._log(f"[*] Executando {self.name}...", "info")

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL, text=True, encoding="utf-8",
            )
            stdout, stderr = proc.communicate(timeout=timeout)

            findings = self.parse_output(stdout, stderr, **kwargs)
            self._log(f"[+] {self.name}: {len(findings)} finding(s)", "success")
            return findings

        except subprocess.TimeoutExpired:
            proc.kill()
            self._log(f"[!] {self.name} timeout ({timeout}s)", "error")
            return []
        except Exception as e:
            self._log(f"[!] {self.name} erro: {e}", "error")
            return []
