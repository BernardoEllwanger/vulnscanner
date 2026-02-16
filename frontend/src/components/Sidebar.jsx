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
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style={{ verticalAlign: "middle", marginRight: 4 }}>
            <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
          </svg>
          Bernardo Ellwanger
        </a>
      </div>
    </aside>
  );
}

export default Sidebar;
