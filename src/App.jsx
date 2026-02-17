import { useState, useEffect } from "react";
import Scanner from "./components/Scanner";
import AdminPanel from "./pages/AdminPanel";
import Login from "./pages/Login";
import Register from "./pages/Register";
import "./index.css";

function App() {
  const [role, setRole] = useState(null);
  const [page, setPage] = useState("dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const savedRole = localStorage.getItem("role");
    if (savedRole) setRole(savedRole);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("role");
    localStorage.removeItem("currentUser");
    setRole(null);
  };

  if (!role) {
    return page === "login" ? (
      <Login onLogin={setRole} goToRegister={() => setPage("register")} />
    ) : (
      <Register goToLogin={() => setPage("login")} />
    );
  }

  return (
    <div className="layout">

      <div className={`sidebar ${collapsed ? "collapsed" : ""} ${mobileOpen ? "mobile-open" : ""}`}>
        <div className="sidebar-header">
          <h2>CyberShield</h2>
          <button onClick={() => setCollapsed(!collapsed)} className="collapse-btn">
            ☰
          </button>
        </div>

        <button onClick={() => setPage("dashboard")}>Dashboard</button>

        {role === "admin" && (
          <button onClick={() => setPage("admin")}>Admin Panel</button>
        )}

        <button onClick={handleLogout} className="logout-btn">
          Logout
        </button>
      </div>

      <div className="main-content">
        <div className="topbar">
          <button className="mobile-menu-btn" onClick={() => setMobileOpen(!mobileOpen)}>
            ☰
          </button>
        </div>

        <div className="page-transition">
          {page === "dashboard" && <Scanner />}
          {page === "admin" && role === "admin" && <AdminPanel />}
        </div>
      </div>
    </div>
  );
}

export default App;