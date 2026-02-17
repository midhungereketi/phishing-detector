function Settings() {
    return (
        <div className="card" style={{ maxWidth: '600px' }}>
            <h2>System Settings</h2>

            <div style={{ marginTop: '30px' }}>
                {[
                    "Enable Real-time Protection",
                    "Auto-update Threat Database",
                    "Desktop Notifications",
                    "Dark Mode (Forced)"
                ].map((setting, i) => (
                    <div key={i} style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '15px 0',
                        borderBottom: '1px solid rgba(255,255,255,0.05)'
                    }}>
                        <span style={{ color: '#e2e8f0' }}>{setting}</span>
                        <div style={{
                            width: '40px',
                            height: '20px',
                            background: i === 0 || i === 3 ? '#8b5cf6' : '#334155',
                            borderRadius: '20px',
                            position: 'relative',
                            cursor: 'pointer'
                        }}>
                            <div style={{
                                width: '16px',
                                height: '16px',
                                background: 'white',
                                borderRadius: '50%',
                                position: 'absolute',
                                top: '2px',
                                left: i === 0 || i === 3 ? '22px' : '2px',
                                transition: 'all 0.3s'
                            }} />
                        </div>
                    </div>
                ))}
            </div>

            <div style={{ marginTop: '30px', textAlign: 'right' }}>
                <button className="primary-btn">Save Changes</button>
            </div>
        </div>
    );
}

export default Settings;
