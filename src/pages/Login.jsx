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
      <h2>🔐 Secure Login</h2>

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
        >
          {showPassword ? "🙈" : "👁"}
        </span>
      </div>

      <button onClick={handleLogin}>Login</button>

      <p>
        New user?{" "}
        <span className="link" onClick={goToRegister}>
          Register here
        </span>
      </p>
    </div>
  );
}

export default Login;