const STORAGE_KEY = "vulnscanner_reports";

export function getLocalReports() {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

export function saveLocalReport(report) {
  try {
    const reports = getLocalReports();
    reports.unshift(report);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(reports));
  } catch {
    // localStorage cheio ou indisponível
  }
}

export function getLocalReport(reportId) {
  const reports = getLocalReports();
  return reports.find((r) => r.id === reportId) || null;
}

export function deleteLocalReport(reportId) {
  try {
    const reports = getLocalReports().filter((r) => r.id !== reportId);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(reports));
  } catch {
    // noop
  }
}

export async function isBackendAvailable() {
  try {
    const resp = await fetch("/api/reports", { signal: AbortSignal.timeout(2000) });
    return resp.ok;
  } catch {
    return false;
  }
}
