import { useState } from "react";
import Sidebar from "./components/Sidebar";
import ScanPanel from "./components/ScanPanel";
import ReportsTab from "./components/ReportsTab";
import ReportDetail from "./components/ReportDetail";
import DiscoveryTab from "./components/DiscoveryTab";
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

  const handleViewReport = (reportId) => {
    setSelectedReport(reportId);
    setTab("report-detail");
  };

  const handleScanComplete = (results) => {
    setAllResults((prev) => [...prev, results]);
  };

  const mergedResults = allResults.length > 0
    ? {
        target: allResults.map((r) => r.target).filter(Boolean).join(", "),
        discovery: {
          pages: [...new Set(allResults.flatMap((r) => r.discovery?.pages || []))],
          api_endpoints: [...new Set(allResults.flatMap((r) => r.discovery?.api_endpoints || []))],
          js_files: [...new Set(allResults.flatMap((r) => r.discovery?.js_files || []))],
          forms: allResults.flatMap((r) => r.discovery?.forms || []).filter(
            (form, i, arr) => arr.findIndex((f) => f.action === form.action && f.page_url === form.page_url) === i
          ),
        },
      }
    : null;

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
        return <DiscoveryTab results={mergedResults} />;
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
