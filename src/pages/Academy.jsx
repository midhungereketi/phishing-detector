function Academy() {
    return (
        <div>
            <div className="card">
                <h2>Cyber Security Academy</h2>
                <p className="text-secondary">Learn the latest defense strategies and threat analysis techniques.</p>

                <div style={{ marginTop: '30px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px' }}>
                    {[
                        { title: "Phishing 101", level: "Beginner", icon: "🎣" },
                        { title: "Network Defense", level: "Intermediate", icon: "🛡️" },
                        { title: "Malware Analysis", level: "Advanced", icon: "🦠" },
                        { title: "Social Engineering", level: "Intermediate", icon: "🗣️" }
                    ].map((course, i) => (
                        <div key={i} className="panel" style={{ cursor: 'pointer', border: '1px solid rgba(139, 92, 246, 0.2)' }}>
                            <div style={{ fontSize: '2rem', marginBottom: '10px' }}>{course.icon}</div>
                            <h3 style={{ fontSize: '1.2rem' }}>{course.title}</h3>
                            <span className="status-badge safe" style={{ marginTop: '10px' }}>{course.level}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}

export default Academy;
