function Welcome({ goToLogin, goToRegister }) {
  return (
    <div className="welcome-container">
      <div className="welcome-card">
        <h1 style={{ fontSize: '3rem', letterSpacing: '4px', marginBottom: '10px' }}>CYBEROPS</h1>
        <p style={{ color: '#94a3b8', marginBottom: '40px', letterSpacing: '1px' }}>
          GLOBAL SECURITY OPERATIONS CENTER
        </p>

        <div style={{ display: 'flex', gap: '20px', justifyContent: 'center' }}>
          <button className="primary-btn" onClick={goToLogin}>Initialize Session</button>
          <button className="secondary-btn" onClick={goToRegister}>
            Request Access
          </button>
        </div>
      </div>
    </div>
  );
}

export default Welcome;