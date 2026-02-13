"""Módulo de ferramentas externas de segurança."""

from tools.nuclei import NucleiTool
from tools.sqlmap import SqlmapTool
from tools.gitleaks import GitleaksTool
from tools.trufflehog import TrufflehogTool

ALL_TOOLS = [NucleiTool, SqlmapTool, GitleaksTool, TrufflehogTool]


class ExternalToolManager:
    def __init__(self, log_callback=None):
        self._log = log_callback
        self.tools = {cls.tool_id: cls(log_callback=log_callback) for cls in ALL_TOOLS}

    def get_status(self) -> list:
        """Retorna status de instalação de todas as ferramentas."""
        result = []
        for tool in self.tools.values():
            installed = tool.is_installed()
            result.append({
                "id": tool.tool_id,
                "name": tool.name,
                "description": tool.description,
                "category": tool.category,
                "installed": installed,
                "version": tool.get_version() if installed else None,
            })
        return result

    def run_selected(self, tool_ids: list, target_url: str, **kwargs) -> list:
        """Executa ferramentas selecionadas e retorna findings unificados."""
        all_findings = []
        for tool_id in tool_ids:
            tool = self.tools.get(tool_id)
            if not tool:
                continue
            findings = tool.run(target_url, **kwargs)
            for f in findings:
                f.setdefault("details", {})["_tool"] = tool.name
            all_findings.extend(findings)
        return all_findings
