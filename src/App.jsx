import { useState, useEffect } from "react";
import Scanner from "./components/Scanner";
import AdminPanel from "./pages/AdminPanel";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Welcome from "./pages/Welcome";
import ThreatMap from "./pages/ThreatMap";
import Academy from "./pages/Academy";
import Settings from "./pages/Settings";
import "./index.css";

function App() {
  const [role, setRole] = useState(null);
  const [page, setPage] = useState("welcome");
  const [isSidebarOpen, setSidebarOpen] = useState(true);

  useEffect(() => {
    const savedRole = localStorage.getItem("role");
    if (savedRole) {
      setRole(savedRole);
      setPage("dashboard");
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("role");
    localStorage.removeItem("currentUser");
    setRole(null);
    setPage("welcome");
  };

  const NavItem = ({ icon, label, target }) => (
    <button
      className={`nav-item ${page === target ? "active" : ""}`}
      onClick={() => setPage(target)}
    >
      <span style={{ marginRight: '10px' }}>{icon}</span> {label}
    </button>
  );

  if (!role) {
    if (page === "welcome")
      return (
        <Welcome
          goToLogin={() => setPage("login")}
          goToRegister={() => setPage("register")}
        />
      );

    if (page === "login")
      return (
        <Login
          onLogin={(r) => {
            setRole(r);
            setPage("dashboard");
          }}
          goToRegister={() => setPage("register")}
        />
      );

    if (page === "register")
      return <Register goToLogin={() => setPage("login")} />;
  }

  return (
    <div className="layout">
      {/* Sidebar */}
      <div className="sidebar">
        <h2>CYBEROPS</h2>

        <div style={{ marginTop: '20px' }}>
          <p style={{ color: '#64748b', fontSize: '0.75rem', paddingLeft: '16px', textTransform: 'uppercase', letterSpacing: '1px' }}>Main</p>
          <NavItem icon="📊" label="Dashboard" target="dashboard" />
          <NavItem icon="🌍" label="Threat Map" target="threat-map" />
          {role === "admin" && (
            <NavItem icon="🛡️" label="Admin Panel" target="admin" />
          )}
        </div>

        <div style={{ marginTop: '20px' }}>
          <p style={{ color: '#64748b', fontSize: '0.75rem', paddingLeft: '16px', textTransform: 'uppercase', letterSpacing: '1px' }}>Resources</p>
          <NavItem icon="🎓" label="Academy" target="academy" />
          <NavItem icon="⚙️" label="Settings" target="settings" />
        </div>

        <button onClick={handleLogout} className="nav-item logout-btn">
          <span style={{ marginRight: '10px' }}>🚪</span> Logout
        </button>
      </div>

      {/* Main Content */}
      <div className="main-content">
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
          <div>
            <h1 style={{ fontSize: '1.5rem', margin: 0 }}>
              {page === "dashboard" && "Mission Control"}
              {page === "threat-map" && "Global Threat Map"}
              {page === "admin" && "Administration"}
              {page === "academy" && "Training Center"}
              {page === "settings" && "System Configuration"}
            </h1>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Welcome back, Operator.</p>
          </div>
          <div className="status-badge safe">
            System Online
          </div>
        </header>

        {page === "dashboard" && <Scanner />}
        {page === "threat-map" && <ThreatMap />}
        {page === "admin" && <AdminPanel />}
        {page === "academy" && <Academy />}
        {page === "settings" && <Settings />}
      </div>
    </div>
  );
}

export default App;