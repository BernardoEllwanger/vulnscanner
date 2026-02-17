import { useState, useRef, useEffect, useCallback } from "react";
import LogViewer from "./LogViewer";
import { saveLocalReport } from "../utils/storage";

const API = import.meta.env.VITE_API_URL || '';

function ScanPanel({ onScanComplete, onViewReport, scanState, setScanState }) {
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [availableTools, setAvailableTools] = useState([]);
  const [selectedTools, setSelectedTools] = useState([]);
  const esRef = useRef(null);

  const scanning = scanState.scanning;
  const logs = scanState.logs;
  const scanId = scanState.scanId;
  const status = scanState.status;

  const updateState = useCallback((patch) => {
    setScanState((s) => ({ ...s, ...patch }));
  }, [setScanState]);

  const appendLog = useCallback((log) => {
    setScanState((s) => ({ ...s, logs: [...s.logs, log] }));
  }, [setScanState]);

  useEffect(() => {
    fetch(`${API}/api/tools/status`)
      .then((r) => r.json())
      .then((tools) => {
        setAvailableTools(tools);
        setSelectedTools(tools.filter((t) => t.installed).map((t) => t.id));
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!scanId || !scanning) return;

    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }

    const es = new EventSource(`${API}/api/scan/${scanId}/logs?from=0`);
    esRef.current = es;

    es.onmessage = (event) => {
      const log = JSON.parse(event.data);
      if (log.msg === "__DONE__") {
        es.close();
        esRef.current = null;
        updateState({ scanning: false, status: "completed" });
        fetch(`${API}/api/scan/${scanId}/results`)
          .then((r) => r.json())
          .then((results) => {
            const report = { id: scanId, ...results };
            saveLocalReport(report);
            onScanComplete(report);
          })
          .catch((err) => console.error("Erro ao buscar resultados:", err));
        return;
      }
      appendLog(log);
    };

    es.onerror = () => {
      es.close();
      esRef.current = null;
      setTimeout(() => {
        fetch(`${API}/api/scan/${scanId}/status`)
          .then((r) => r.json())
          .then((data) => {
            if (data.status === "completed") {
              updateState({ scanning: false, status: "completed" });
              fetch(`${API}/api/scan/${scanId}/results`)
                .then((r) => r.json())
                .then((results) => {
                  const report = { id: scanId, ...results };
                  saveLocalReport(report);
                  onScanComplete(report);
                })
                .catch((err) => console.error("Erro ao buscar resultados:", err));
            } else if (data.status === "error") {
              updateState({ scanning: false, status: "error" });
            } else {
              updateState({ scanning: false, status: "error" });
              appendLog({ time: "--:--:--", level: "error", msg: "Conexão SSE perdida. Recarregue a página." });
            }
          })
          .catch(() => {
            updateState({ scanning: false, status: "error" });
          });
      }, 1000);
    };

    return () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, [scanId, scanning]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleTool = (toolId) => {
    setSelectedTools((prev) =>
      prev.includes(toolId) ? prev.filter((t) => t !== toolId) : [...prev, toolId]
    );
  };

  const startScan = async () => {
    if (!url.trim()) return;

    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }

    updateState({ scanning: true, logs: [], status: "starting", scanId: null });

    try {
      const resp = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: url.trim(),
          token: token.trim() || null,
          login_url: loginUrl.trim() || null,
          username: username.trim() || null,
          password: password.trim() || null,
          external_tools: selectedTools.length > 0 ? selectedTools : undefined,
        }),
      });

      const data = await resp.json();
      if (!resp.ok) {
        updateState({
          scanning: false,
          status: "error",
          logs: [{ time: "--:--:--", level: "error", msg: data.error || "Erro ao iniciar scan" }],
        });
        return;
      }

      updateState({ scanId: data.scan_id, status: "running" });

    } catch (err) {
      updateState({
        scanning: false,
        status: "error",
        logs: [{ time: "--:--:--", level: "error", msg: `Erro de conexão: ${err.message}` }],
      });
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1>Novo Scan</h1>
        <p>Configure e execute uma varredura de vulnerabilidades</p>
      </div>

      <div className="card">
        <h3>Configuração</h3>
        <div className="form-group">
          <label>URL Alvo *</label>
          <input
            type="text"
            placeholder="https://meusite.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={scanning}
          />
        </div>

        <div className="form-group">
          <label>Bearer Token</label>
          <input
            type="text"
            placeholder="eyJhbGciOi..."
            value={token}
            onChange={(e) => setToken(e.target.value)}
            disabled={scanning}
          />
        </div>

        <button
          className="collapsible-toggle"
          onClick={() => setShowAuth(!showAuth)}
          style={{ marginBottom: 12 }}
        >
          {showAuth ? "▾ Ocultar Login via Formulário" : "▸ Login via Formulário (opcional)"}
        </button>

        {showAuth && (
          <>
            <div className="form-group">
              <label>URL da Página de Login</label>
              <input
                type="text"
                placeholder="https://meusite.com/login"
                value={loginUrl}
                onChange={(e) => setLoginUrl(e.target.value)}
                disabled={scanning}
              />
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>Usuário</label>
                <input
                  type="text"
                  placeholder="admin"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={scanning}
                />
              </div>
              <div className="form-group">
                <label>Senha</label>
                <input
                  type="password"
                  placeholder="********"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={scanning}
                />
              </div>
            </div>
          </>
        )}

        <h3 style={{ marginTop: 16 }}>Ferramentas Externas</h3>
        <div className="tools-section">
          {availableTools.length === 0 && (
            <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
              Carregando ferramentas...
            </p>
          )}
          {availableTools.map((tool) => (
            <label
              key={tool.id}
              className={`tool-checkbox ${!tool.installed ? "tool-missing" : ""}`}
            >
              <input
                type="checkbox"
                checked={selectedTools.includes(tool.id)}
                onChange={() => toggleTool(tool.id)}
                disabled={!tool.installed || scanning}
              />
              <span className="tool-name">{tool.name}</span>
              <span className={`badge ${tool.installed ? "badge-completed" : "badge-error"}`} style={{ fontSize: "0.65rem", padding: "2px 6px" }}>
                {tool.installed ? "Instalado" : "Não encontrado"}
              </span>
              <span className="tool-desc">{tool.description}</span>
            </label>
          ))}
        </div>

        <div className="actions-row">
          <button
            className="btn btn-primary"
            onClick={startScan}
            disabled={scanning || !url.trim()}
          >
            {scanning ? "Escaneando..." : "Iniciar Scan"}
          </button>
          {status === "completed" && scanId && (
            <button className="btn btn-secondary" onClick={() => onViewReport(scanId)}>
              Ver Relatório
            </button>
          )}
        </div>
      </div>

      {(scanning || logs.length > 0) && (
        <div className="card">
          <h3>
            Log em Tempo Real
            {status && (
              <span className={`badge badge-${status}`} style={{ marginLeft: 12, fontSize: "0.7rem" }}>
                {status === "running" ? "em andamento" : status === "completed" ? "finalizado" : status}
              </span>
            )}
          </h3>
          <LogViewer logs={logs} />
        </div>
      )}
    </div>
  );
}

export default ScanPanel;
