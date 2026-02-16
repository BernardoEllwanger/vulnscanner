function Sidebar({ activeTab, onTabChange, hasResults }) {
  const items = [
    { id: "scan", icon: "▶", label: "Novo Scan" },
    { id: "reports", icon: "📋", label: "Relatórios" },
    { id: "discovery", icon: "🔍", label: "Reconhecimento", disabled: !hasResults },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <h2>VulnScanner</h2>
        <span>Dashboard</span>
      </div>
      <nav className="sidebar-nav">
        {items.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${activeTab === item.id ? "active" : ""} ${item.disabled ? "disabled" : ""}`}
            onClick={() => !item.disabled && onTabChange(item.id)}
          >
            <span>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <a href="https://www.linkedin.com/in/bernardo-ellwanger" target="_blank" rel="noopener noreferrer">
          Bernardo Ellwanger
        </a>
      </div>
    </aside>
  );
}

export default Sidebar;
