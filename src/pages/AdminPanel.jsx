import { useResource } from '../hooks';
import { formatDate } from '../api';
export default function AdminPanel() {
  const logs = useResource('/admin/logs');
  return <><div className="page-heading"><div><div className="eyebrow">ADMINISTRATOR VIEW</div><h1>Activity logs<span className="heading-dot">.</span></h1><p>Server-recorded actions across the application.</p></div><button className="secondary-btn" onClick={logs.refresh} disabled={logs.loading}>Refresh</button></div>{logs.error && <div className="notice error">{logs.error}</div>}<section className="card">{logs.loading ? <p>Loading activity…</p> : !logs.data?.length ? <div className="empty-state">No activity recorded.</div> : <div className="table-responsive"><table><thead><tr><th>User</th><th>Action</th><th>Time</th></tr></thead><tbody>{logs.data.map(log => <tr key={log.id}><td>{log.username}</td><td>{log.action}</td><td>{formatDate(log.created_at)}</td></tr>)}</tbody></table></div>}<p className="small">Latest 200 actions. Scan content and passwords are excluded.</p></section></>;
}
