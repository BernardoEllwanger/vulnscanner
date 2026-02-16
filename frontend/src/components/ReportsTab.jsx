import { useEffect, useState } from "react";
import { getLocalReports, deleteLocalReport } from "../utils/storage";

function ReportsTab({ onViewReport }) {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadReports = () => {
    setLoading(true);
    const local = getLocalReports().map((r) => ({
      id: r.id,
      target: r.target || "?",
      timestamp: r.timestamp || "?",
      stats: r.stats || {},
    }));
    setReports(local);
    setLoading(false);
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleDelete = (e, reportId) => {
    e.stopPropagation();
    if (!confirm("Excluir este relatório?")) return;
    deleteLocalReport(reportId);
    loadReports();
  };

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1>Relatórios</h1>
        </div>
        <div className="empty-state"><p>Carregando...</p></div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <h1>Relatórios</h1>
        <p>{reports.length} relatório(s) salvos</p>
      </div>

      {reports.length === 0 ? (
        <div className="empty-state">
          <h3>Nenhum relatório</h3>
          <p>Execute um scan para gerar o primeiro relatório.</p>
        </div>
      ) : (
        reports.map((r) => (
          <div
            key={r.id}
            className="report-card"
            onClick={() => onViewReport(r.id)}
          >
            <div className="report-info">
              <h4>{r.target}</h4>
              <p>{r.timestamp}</p>
            </div>
            <div className="report-stats">
              <div className="mini-stat">
                <div className="num" style={{ color: "var(--accent)" }}>
                  {r.stats?.total_findings ?? "?"}
                </div>
                <div className="lbl">Findings</div>
              </div>
              <div className="mini-stat">
                <div className="num">{r.stats?.pages_found ?? "?"}</div>
                <div className="lbl">Páginas</div>
              </div>
              <div className="mini-stat">
                <div className="num">{r.stats?.api_endpoints_found ?? "?"}</div>
                <div className="lbl">APIs</div>
              </div>
              <button className="btn btn-danger btn-sm" onClick={(e) => handleDelete(e, r.id)}>
                Excluir
              </button>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

export default ReportsTab;
