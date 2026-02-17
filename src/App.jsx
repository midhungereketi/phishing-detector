import { useState, useEffect } from "react";
import Scanner from "./components/Scanner";
import AdminPanel from "./pages/AdminPanel";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Welcome from "./pages/Welcome";
import "./index.css";

function App() {
  const [role, setRole] = useState(null);
  const [page, setPage] = useState("welcome");
  const [collapsed, setCollapsed] = useState(false);

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
      <div className={`sidebar ${collapsed ? "collapsed" : ""}`}>
        <h2>CYBERSHIELD</h2>

        <button onClick={() => setPage("dashboard")}>Dashboard</button>
        {role === "admin" && (
          <button onClick={() => setPage("admin")}>Admin Panel</button>
        )}

        <button onClick={handleLogout} className="logout-btn">
          Logout
        </button>
      </div>

      <div className="main-content">
        {page === "dashboard" && <Scanner />}
        {page === "admin" && <AdminPanel />}
      </div>
    </div>
  );
}

export default App;