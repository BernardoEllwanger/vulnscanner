import { useState, useEffect } from "react";
import Sidebar from "./components/Sidebar";
import ScanPanel from "./components/ScanPanel";
import ReportsTab from "./components/ReportsTab";
import ReportDetail from "./components/ReportDetail";
import DiscoveryTab from "./components/DiscoveryTab";
import { getLocalReports } from "./utils/storage";
import "./App.css";

function App() {
  const [tab, setTab] = useState("scan");
  const [selectedReport, setSelectedReport] = useState(null);
  const [allResults, setAllResults] = useState([]);

  const [scanState, setScanState] = useState({
    scanning: false,
    logs: [],
    scanId: null,
    status: null,
  });

  useEffect(() => {
    const stored = getLocalReports();
    if (stored.length > 0) {
      setAllResults(stored);
    }
  }, []);

  const handleViewReport = (reportId) => {
    setSelectedReport(reportId);
    setTab("report-detail");
  };

  const handleScanComplete = (report) => {
    setAllResults((prev) => {
      const exists = prev.some((r) => r.id === report.id);
      return exists ? prev : [...prev, report];
    });
  };

  const renderContent = () => {
    switch (tab) {
      case "scan":
        return (
          <ScanPanel
            onScanComplete={handleScanComplete}
            onViewReport={handleViewReport}
            scanState={scanState}
            setScanState={setScanState}
          />
        );
      case "reports":
        return <ReportsTab onViewReport={handleViewReport} />;
      case "report-detail":
        return (
          <ReportDetail
            reportId={selectedReport}
            onBack={() => setTab("reports")}
          />
        );
      case "discovery":
        return <DiscoveryTab reports={allResults} />;
      default:
        return (
          <ScanPanel
            onScanComplete={handleScanComplete}
            onViewReport={handleViewReport}
            scanState={scanState}
            setScanState={setScanState}
          />
        );
    }
  };

  return (
    <div className="app">
      <div className="mobile-header">
        <h2>VulnScanner</h2>
        <a href="https://www.linkedin.com/in/bernardo-ellwanger" target="_blank" rel="noopener noreferrer">
          Bernardo Ellwanger
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style={{ verticalAlign: "middle", marginLeft: 4 }}>
            <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
          </svg>
        </a>
      </div>
      <Sidebar
        activeTab={tab}
        onTabChange={setTab}
        hasResults={allResults.length > 0}
      />
      <main className="main-content">{renderContent()}</main>
    </div>
  );
}

export default App;
