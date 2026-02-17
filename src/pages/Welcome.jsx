function Welcome({ goToLogin, goToRegister }) {
  return (
    <div className="welcome-container">
      <div className="welcome-card">
        <h1 className="welcome-title">🛡 CYBERSHIELD</h1>
        <p className="welcome-subtitle">
          Advanced Phishing Detection & Security Monitoring System
        </p>

        <div className="welcome-buttons">
          <button onClick={goToLogin}>Login</button>
          <button onClick={goToRegister} className="secondary-btn">
            Sign Up
          </button>
        </div>
      </div>
    </div>
  );
}

export default Welcome;