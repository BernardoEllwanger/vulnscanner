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

  const handleScanComplete = (results) => {
    setAllResults((prev) => [...prev, results]);
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
