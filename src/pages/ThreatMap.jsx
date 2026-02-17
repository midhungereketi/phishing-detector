function ThreatMap() {
    return (
        <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h2>Global Threat Map</h2>
                <span className="status-badge warning">Live Monitoring</span>
            </div>

            <div style={{
                height: '400px',
                background: 'radial-gradient(circle at center, #1e293b 0%, #0f172a 100%)',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#64748b',
                border: '1px dashed #334155'
            }}>
                <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '40px', marginBottom: '10px' }}>🗺️</div>
                    <p>Interactive Threat Map Loading...</p>
                    <p style={{ fontSize: '0.8rem', marginTop: '10px' }}>Connecting to secure nodes...</p>
                </div>
            </div>
        </div>
    );
}

export default ThreatMap;
