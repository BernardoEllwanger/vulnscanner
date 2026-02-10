import { useState } from "react";

function DiscoveryTab({ results }) {
  const [subTab, setSubTab] = useState("pages");

  if (!results) {
    return (
      <div>
        <div className="page-header">
          <h1>Discovery</h1>
        </div>
        <div className="empty-state">
          <h3>Sem dados</h3>
          <p>Execute um scan primeiro para visualizar os dados de discovery.</p>
        </div>
      </div>
    );
  }

  const discovery = results.discovery || {};
  const pages = discovery.pages || [];
  const apis = discovery.api_endpoints || [];
  const jsFiles = discovery.js_files || [];
  const forms = discovery.forms || [];

  const tabs = [
    { id: "pages", label: `Páginas (${pages.length})` },
    { id: "apis", label: `API Endpoints (${apis.length})` },
    { id: "js", label: `Arquivos JS (${jsFiles.length})` },
    { id: "forms", label: `Formulários (${forms.length})` },
  ];

  return (
    <div>
      <div className="page-header">
        <h1>Discovery</h1>
        <p>Todos os recursos descobertos durante o scan de {results.target}</p>
      </div>

      <div className="stats-grid">
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

export default DiscoveryTab;
