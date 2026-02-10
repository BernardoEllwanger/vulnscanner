import { useEffect, useRef } from "react";

function LogViewer({ logs }) {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="log-viewer">
      {logs.length === 0 && (
        <div style={{ color: "var(--text-secondary)" }}>
          Aguardando início do scan...
        </div>
      )}
      {logs.map((log, i) => (
        <div key={i} className={`log-line ${log.level || "info"}`}>
          <span className="time">[{log.time}]</span>
          {log.msg}
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}

export default LogViewer;
