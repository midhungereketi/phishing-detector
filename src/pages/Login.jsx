import { useState } from "react";
import bcrypt from "bcryptjs";

function Login({ onLogin, goToRegister }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const handleLogin = async () => {
    const users = JSON.parse(localStorage.getItem("users")) || [];

    if (username === "admin" && password === "1234") {
      localStorage.setItem("role", "admin");
      localStorage.setItem("currentUser", "admin");
      onLogin("admin");
      return;
    }

    const foundUser = users.find((u) => u.username === username);

    if (!foundUser) {
      alert("Invalid credentials!");
      return;
    }

    const passwordMatch = await bcrypt.compare(
      password,
      foundUser.password
    );

    if (passwordMatch) {
      localStorage.setItem("role", "user");
      localStorage.setItem("currentUser", username);
      onLogin("user");
    } else {
      alert("Invalid credentials!");
    }
  };

  return (
    <div className="auth-container">
      <h2>Please Login</h2>
      <p style={{ marginBottom: '30px', color: '#94a3b8' }}>Identify yourself to access CyberOps</p>

      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />

      <div className="password-wrapper">
        <input
          type={showPassword ? "text" : "password"}
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <span
          className="eye-icon"
          onClick={() => setShowPassword(!showPassword)}
          style={{ cursor: 'pointer', position: 'absolute', right: '15px', top: '50%', transform: 'translateY(-50%)' }}
        >
          {showPassword ? "🙈" : "👁"}
        </span>
      </div>

      <button className="primary-btn w-full" onClick={handleLogin}>Establish Connection</button>

      <p className="mt-4" style={{ fontSize: '0.9rem', color: '#64748b' }}>
        New personnel?{" "}
        <span className="link" onClick={goToRegister} style={{ color: '#06b6d4', cursor: 'pointer' }}>
          Register Access
        </span>
      </p>
    </div>
  );
}

export default Login;