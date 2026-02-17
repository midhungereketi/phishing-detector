import { useState, useEffect } from "react";
import Scanner from "./components/Scanner";
import Login from "./pages/Login";
import Register from "./pages/Register";
import AdminPanel from "./pages/AdminPanel";
import "./index.css";

function App() {
  const [role, setRole] = useState(null);
  const [page, setPage] = useState("dashboard");
  const [theme, setTheme] = useState("dark");
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const savedRole = localStorage.getItem("role");
    if (savedRole) setRole(savedRole);

    const savedTheme = localStorage.getItem("theme");
    if (savedTheme) setTheme(savedTheme);

    const interval = setInterval(() => {
      setTime(new Date());
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    document.body.className = theme;
    localStorage.setItem("theme", theme);
  }, [theme]);

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
      <div className="cyber-bg"></div>

      <div className="sidebar">
        <h2 className="logo">CyberShield</h2>
        <div className="clock">{time.toLocaleTimeString()}</div>

        <button onClick={() => setPage("dashboard")}>Dashboard</button>

        {role === "admin" && (
          <button onClick={() => setPage("admin")}>Admin Panel</button>
        )}

        <button onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          Toggle Theme
        </button>

        <button onClick={handleLogout} className="logout-btn">
          Logout
        </button>
      </div>

      <div className="main-content">
        {page === "dashboard" && <Scanner />}
        {page === "admin" && role === "admin" && <AdminPanel />}
      </div>
    </div>
  );
}

export default App;