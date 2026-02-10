import { useEffect, useState } from "react";
import { getLocalReport } from "../utils/storage";

const SEVERITY_BADGE = {
  "CRÍTICO": "critico",
  "ALTO": "alto",
  "MÉDIO": "medio",
  "BAIXO": "baixo",
  "INFO": "info",
};

function ReportDetail({ reportId, onBack }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterSev, setFilterSev] = useState("ALL");

  useEffect(() => {
    if (!reportId) return;
    setLoading(true);
    fetch(`/api/reports/${reportId}`)
      .then((r) => {
        if (!r.ok) throw new Error("not found");
        return r.json();
      })
      .then((data) => {
        setReport(data);
        setLoading(false);
      })
      .catch(() => {
        const local = getLocalReport(reportId);
        if (local) setReport(local);
        setLoading(false);
      });
  }, [reportId]);

  if (loading) {
    return <div className="empty-state"><p>Carregando relatório...</p></div>;
  }

  if (!report) {
    return <div className="empty-state"><h3>Relatório não encontrado</h3></div>;
  }

  const findings = report.findings || [];
  const filtered = filterSev === "ALL" ? findings : findings.filter((f) => f.severity === filterSev);

  const counts = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  return (
    <div>
      <button className="back-link" onClick={onBack}>
        ← Voltar aos Relatórios
      </button>

      <div className="page-header">
        <h1>{report.target}</h1>
        <p>{report.timestamp}</p>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="value">{report.stats?.pages_found ?? 0}</div>
          <div className="label">Páginas</div>
        </div>
        <div className="stat-card">
          <div className="value">{report.stats?.forms_found ?? 0}</div>
          <div className="label">Formulários</div>
        </div>
        <div className="stat-card">
          <div className="value">{report.stats?.api_endpoints_found ?? 0}</div>
          <div className="label">API Endpoints</div>
        </div>
        <div className="stat-card">
          <div className="value">{report.stats?.js_files_analyzed ?? 0}</div>
          <div className="label">Arquivos JS</div>
        </div>
        <div className="stat-card">
          <div className="value">{report.stats?.total_findings ?? 0}</div>
          <div className="label">Vulnerabilidades</div>
        </div>
      </div>

      <div className="card">
        <h3>Resumo de Severidade</h3>
        <div className="severity-summary">
          {["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"].map((sev) => (
            <span
              key={sev}
              className={`badge badge-${SEVERITY_BADGE[sev]}`}
              style={{ cursor: "pointer", padding: "6px 14px", fontSize: "0.8rem" }}
              onClick={() => setFilterSev(filterSev === sev ? "ALL" : sev)}
            >
              {sev}: {counts[sev] || 0}
              {filterSev === sev && " ✓"}
            </span>
          ))}
          {filterSev !== "ALL" && (
            <button className="collapsible-toggle" onClick={() => setFilterSev("ALL")}>
              Limpar filtro
            </button>
          )}
        </div>
      </div>

      <div className="card">
        <h3>
          Vulnerabilidades ({filtered.length})
        </h3>
        {filtered.length === 0 ? (
          <div className="empty-state" style={{ padding: 20 }}>
            <p>Nenhuma vulnerabilidade {filterSev !== "ALL" ? `com severidade ${filterSev}` : "encontrada"}.</p>
          </div>
        ) : (
          filtered.map((f, i) => (
            <div key={i} className="finding-card">
              <div className="finding-header">
                <span className={`badge badge-${SEVERITY_BADGE[f.severity]}`}>{f.severity}</span>
                <h4>{f.category}</h4>
                {f.details?._tool && (
                  <span className="badge badge-info" style={{ marginLeft: 8 }}>
                    {f.details._tool}
                  </span>
                )}
              </div>
              <div className="finding-details">
                {Object.entries(f.details || {}).filter(([key]) => key !== "_tool").map(([key, val]) => (
                  <div key={key} style={{ display: "contents" }}>
                    <span className="detail-key">{key}:</span>
                    <span className="detail-value">{String(val).substring(0, 500)}</span>
                  </div>
                ))}
              </div>
            </div>
          ))
        )}
      </div>

      <div className="actions-row" style={{ marginTop: 16 }}>
        <button
          className="btn btn-secondary"
          onClick={() => window.open(`/api/reports/${reportId}/html`, "_blank")}
        >
          Abrir HTML
        </button>
      </div>
    </div>
  );
}

export default ReportDetail;
