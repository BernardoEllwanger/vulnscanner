#!/usr/bin/env python3
"""
Backend Flask para o Dashboard do VulnScanner.
Fornece API REST + SSE para execução e visualização de scans.
"""

import json
import os
import shutil
import tempfile
import threading
import time
import uuid

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS

from scanner import VulnScanner
from tools import ExternalToolManager

_tools_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools_bin")
if os.path.isdir(_tools_bin) and _tools_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + _tools_bin

app = Flask(__name__, static_folder="frontend/dist", static_url_path="")
CORS(app, resources={r"/api/*": {"origins": "*"}})


# ---------------------------------------------------------------------------
# Estado dos scans em memória
# ---------------------------------------------------------------------------

scans = {}  # scan_id -> { status, logs, results, thread, done_event }


def _run_scan(scan_id, target_url, token, login_url, username, password, external_tools=None):
    """Executa o scan em background e alimenta a lista de logs."""
    scan = scans[scan_id]
    scan["status"] = "running"
    scan["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")

    def log_callback(msg, level="info"):
        scan["logs"].append({"time": time.strftime("%H:%M:%S"), "level": level, "msg": msg})

    try:
        scanner = VulnScanner(
            target_url=target_url,
            token=token or None,
            login_url=login_url or None,
            username=username or None,
            password=password or None,
            log_callback=log_callback,
        )

        scanner.run()

        if external_tools:
            log_callback("[*] Executando ferramentas externas...", "info")
            tool_manager = ExternalToolManager(log_callback=log_callback)

            tmp_source = None
            secret_tools = {"gitleaks", "trufflehog"}
            has_secret_tools = bool(set(external_tools) & secret_tools)

            if has_secret_tools:
                tmp_source = tempfile.mkdtemp(prefix="vulnscan_src_")
                try:
                    for js_url, js_text in getattr(scanner, "_js_texts", {}).items():
                        safe_name = js_url.split("/")[-1].split("?")[0] or "script.js"
                        with open(os.path.join(tmp_source, safe_name), "w", encoding="utf-8") as f:
                            f.write(js_text)
                    for i, page_url in enumerate(getattr(scanner, "visited", [])):
                        try:
                            resp = scanner.session.get(page_url, timeout=5)
                            fname = f"page_{i}.html"
                            with open(os.path.join(tmp_source, fname), "w", encoding="utf-8") as f:
                                f.write(resp.text)
                        except Exception:
                            pass
                    log_callback(f"[*] Conteúdo do alvo salvo em diretório temporário para análise de segredos", "info")
                except Exception as e:
                    log_callback(f"[!] Erro ao salvar conteúdo para análise: {e}", "warning")

            try:
                kwargs = {}
                if tmp_source:
                    kwargs["source_path"] = tmp_source
                ext_findings = tool_manager.run_selected(external_tools, target_url, **kwargs)
                for f in ext_findings:
                    scanner.findings.append((f["severity"], f["category"], f["details"]))
                log_callback(f"[+] Ferramentas externas: {len(ext_findings)} finding(s) adicionais", "success")
            finally:
                if tmp_source and os.path.exists(tmp_source):
                    shutil.rmtree(tmp_source, ignore_errors=True)

        scan["results"] = scanner.get_structured_results()
        scan["status"] = "completed"
        log_callback("[+] Scan finalizado com sucesso!", "success")

    except Exception as e:
        scan["status"] = "error"
        scan["error"] = str(e)
        scan["logs"].append({"time": time.strftime("%H:%M:%S"), "level": "error", "msg": f"[!] Erro: {e}"})

    finally:
        scan["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        scan["done_event"].set()


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Inicia um novo scan em background."""
    data = request.get_json() or {}

    target_url = data.get("url", "").strip()
    if not target_url:
        return jsonify({"error": "URL é obrigatória"}), 400
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    scan_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    external_tools = data.get("external_tools", [])

    scans[scan_id] = {
        "id": scan_id,
        "target": target_url,
        "status": "starting",
        "logs": [],
        "results": None,
        "error": None,
        "started_at": None,
        "finished_at": None,
        "done_event": threading.Event(),
    }

    t = threading.Thread(
        target=_run_scan,
        args=(scan_id, target_url, data.get("token"), data.get("login_url"),
              data.get("username"), data.get("password"), external_tools),
        daemon=True,
    )
    scans[scan_id]["thread"] = t
    t.start()

    return jsonify({"scan_id": scan_id}), 202


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    """Retorna o status atual do scan."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan não encontrado"}), 404

    return jsonify({
        "id": scan_id,
        "target": scan["target"],
        "status": scan["status"],
        "started_at": scan["started_at"],
        "finished_at": scan["finished_at"],
        "log_count": len(scan["logs"]),
        "error": scan["error"],
    })


@app.route("/api/scan/<scan_id>/logs")
def scan_logs_sse(scan_id):
    """SSE stream dos logs em tempo real."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan não encontrado"}), 404

    from_idx = int(request.args.get("from", 0))

    def generate():
        idx = from_idx
        while True:
            while idx < len(scan["logs"]):
                log = scan["logs"][idx]
                data = json.dumps(log, ensure_ascii=False)
                yield f"data: {data}\n\n"
                idx += 1

            if scan["done_event"].is_set() and idx >= len(scan["logs"]):
                yield f"data: {json.dumps({'msg': '__DONE__', 'level': 'system'})}\n\n"
                break

            time.sleep(0.3)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/scan/<scan_id>/results")
def scan_results(scan_id):
    """Retorna os resultados estruturados do scan."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan não encontrado"}), 404
    if scan["status"] == "running":
        return jsonify({"error": "Scan ainda em andamento"}), 202
    if scan["results"]:
        return jsonify(scan["results"])

    return jsonify({"error": "Resultados não encontrados"}), 404


# ---------------------------------------------------------------------------
# Ferramentas Externas
# ---------------------------------------------------------------------------

@app.route("/api/tools/status")
def tools_status():
    """Retorna status de instalação das ferramentas externas."""
    manager = ExternalToolManager()
    return jsonify(manager.get_status())


# ---------------------------------------------------------------------------
# Serve o React SPA (produção)
# ---------------------------------------------------------------------------

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_spa(path):
    """Serve o frontend React (build estático)."""
    if path and os.path.exists(os.path.join(app.static_folder or "", path)):
        return send_from_directory(app.static_folder, path)
    index_path = os.path.join(app.static_folder or "", "index.html")
    if os.path.exists(index_path):
        return send_from_directory(app.static_folder, "index.html")
    return jsonify({"message": "Backend rodando. Frontend não encontrado. Execute: cd frontend && npm run build"}), 200


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"\n{'='*50}")
    print("  VulnScanner Dashboard - Backend")
    print(f"  http://localhost:5000")
    print(f"{'='*50}\n")
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
