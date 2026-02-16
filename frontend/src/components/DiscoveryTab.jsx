import { useState } from "react";

function DiscoveryTab({ results }) {
  const [subTab, setSubTab] = useState("infra");

  if (!results) {
    return (
      <div>
        <div className="page-header">
          <h1>Reconhecimento</h1>
        </div>
        <div className="empty-state">
          <h3>Sem dados</h3>
          <p>Execute um scan primeiro para visualizar os dados de reconhecimento.</p>
        </div>
      </div>
    );
  }

  const recon = results.recon || {};
  const discovery = results.discovery || {};
  const pages = discovery.pages || [];
  const apis = discovery.api_endpoints || [];
  const jsFiles = discovery.js_files || [];
  const forms = discovery.forms || [];
  const openPorts = recon.open_ports || [];
  const serverInfo = recon.server_info || {};

  const tabs = [
    { id: "infra", label: "Infraestrutura" },
    { id: "pages", label: `Páginas (${pages.length})` },
    { id: "apis", label: `API Endpoints (${apis.length})` },
    { id: "js", label: `Arquivos JS (${jsFiles.length})` },
    { id: "forms", label: `Formulários (${forms.length})` },
  ];

  return (
    <div>
      <div className="page-header">
        <h1>Reconhecimento</h1>
        <p>Recursos descobertos durante a varredura de {results.target}</p>
      </div>

      <div className="stats-grid">
        {recon.ip && (
          <div className="stat-card">
            <div className="value" style={{ fontSize: "1rem" }}>{recon.ip}</div>
            <div className="label">IP do Alvo</div>
          </div>
        )}
        <div className="stat-card">
          <div className="value">{openPorts.length}</div>
          <div className="label">Portas Abertas</div>
        </div>
        <div className="stat-card">
          <div className="value">{pages.length}</div>
          <div className="label">Páginas</div>
        </div>
        <div className="stat-card">
          <div className="value">{apis.length}</div>
          <div className="label">API Endpoints</div>
        </div>
        <div className="stat-card">
          <div className="value">{jsFiles.length}</div>
          <div className="label">Arquivos JS</div>
        </div>
        <div className="stat-card">
          <div className="value">{forms.length}</div>
          <div className="label">Formulários</div>
        </div>
      </div>

      <div className="tabs">
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`tab-btn ${subTab === t.id ? "active" : ""}`}
            onClick={() => setSubTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="card">
        {subTab === "infra" && (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: "8px 16px", marginBottom: 16 }}>
              <span style={{ color: "var(--text-secondary)", fontWeight: 600 }}>IP:</span>
              <span><code>{recon.ip || "N/A"}</code></span>
              <span style={{ color: "var(--text-secondary)", fontWeight: 600 }}>Portas Abertas:</span>
              <span>
                {openPorts.length > 0 ? openPorts.map((p) => (
                  <code key={p} style={{ marginRight: 6 }}>{p}</code>
                )) : <span style={{ color: "var(--text-secondary)" }}>Nenhuma porta adicional detectada</span>}
              </span>
              {Object.entries(serverInfo).map(([key, val]) => (
                <span key={key} style={{ display: "contents" }}>
                  <span style={{ color: "var(--text-secondary)", fontWeight: 600 }}>{key}:</span>
                  <span><code>{val}</code></span>
                </span>
              ))}
            </div>
            {openPorts.length > 0 && (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Porta</th>
                    <th>Serviço Comum</th>
                  </tr>
                </thead>
                <tbody>
                  {openPorts.map((port) => (
                    <tr key={port}>
                      <td><code>{port}</code></td>
                      <td style={{ color: "var(--text-secondary)" }}>{getServiceName(port)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {subTab === "pages" && (
          pages.length === 0 ? (
            <p style={{ color: "var(--text-secondary)" }}>Nenhuma página encontrada.</p>
          ) : (
            <ul className="discovery-list">
              {pages.map((url, i) => (
                <li key={i}>
                  <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent)", textDecoration: "none" }}>
                    {url}
                  </a>
                </li>
              ))}
            </ul>
          )
        )}

        {subTab === "apis" && (
          apis.length === 0 ? (
            <p style={{ color: "var(--text-secondary)" }}>Nenhum endpoint de API encontrado.</p>
          ) : (
            <ul className="discovery-list">
              {apis.map((url, i) => (
                <li key={i}>
                  <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent)", textDecoration: "none" }}>
                    {url}
                  </a>
                </li>
              ))}
            </ul>
          )
        )}

        {subTab === "js" && (
          jsFiles.length === 0 ? (
            <p style={{ color: "var(--text-secondary)" }}>Nenhum arquivo JS encontrado.</p>
          ) : (
            <ul className="discovery-list">
              {jsFiles.map((url, i) => (
                <li key={i}>
                  <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent)", textDecoration: "none" }}>
                    {url}
                  </a>
                </li>
              ))}
            </ul>
          )
        )}

        {subTab === "forms" && (
          forms.length === 0 ? (
            <p style={{ color: "var(--text-secondary)" }}>Nenhum formulário encontrado.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Página</th>
                  <th>Método</th>
                  <th>Action</th>
                  <th>Campos</th>
                </tr>
              </thead>
              <tbody>
                {forms.map((form, i) => (
                  <tr key={i}>
                    <td><code>{form.page_url}</code></td>
                    <td>
                      <span className={`badge ${form.method === "POST" ? "badge-alto" : "badge-info"}`}>
                        {form.method}
                      </span>
                      {form.source === "dynamic" && (
                        <span className="badge badge-medio" style={{ marginLeft: 4, fontSize: "0.6rem" }}>SPA</span>
                      )}
                    </td>
                    <td><code>{form.action}</code></td>
                    <td>
                      {Object.keys(form.fields || {}).map((f) => (
                        <code key={f} style={{ marginRight: 6 }}>{f}</code>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </div>
    </div>
  );
}

function getServiceName(port) {
  const services = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP Proxy", 8443: "HTTPS Alt", 27017: "MongoDB",
  };
  return services[port] || "Desconhecido";
}

export default DiscoveryTab;
