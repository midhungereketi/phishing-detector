import { useEffect, useState } from "react";

function AdminPanel() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const savedLogs =
      JSON.parse(localStorage.getItem("activityLogs")) || [];
    setLogs(savedLogs);
  }, []);

  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h2>Activity Logs</h2>

      <div className="table-responsive">
        <table className="modern-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Action Details</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {logs.length > 0 ? (
              logs.map((log, index) => (
                <tr key={index}>
                  <td style={{ fontWeight: '500', color: '#8b5cf6' }}>{log.username}</td>
                  <td>{log.action}</td>
                  <td style={{ color: '#64748b' }}>{log.time}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="3" style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>No logs recorded</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AdminPanel;