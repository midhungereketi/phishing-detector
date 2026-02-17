import { useEffect, useState } from "react";

function AdminPanel() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const savedLogs =
      JSON.parse(localStorage.getItem("activityLogs")) || [];
    setLogs(savedLogs);
  }, []);

  return (
    <div style={{ marginTop: "40px", padding: "20px", background: "#111827", borderRadius: "10px" }}>
      <h2>Admin Activity Logs</h2>

      <table style={{ width: "100%", marginTop: "15px" }}>
        <thead>
          <tr>
            <th>User</th>
            <th>Action</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, index) => (
            <tr key={index}>
              <td>{log.username}</td>
              <td>{log.action}</td>
              <td>{log.time}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default AdminPanel;