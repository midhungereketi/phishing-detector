import { useState } from "react";
import bcrypt from "bcryptjs";

function Register({ goToLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const handleRegister = async () => {
    if (!username || !password) {
      alert("Fill all fields");
      return;
    }

    const users = JSON.parse(localStorage.getItem("users")) || [];

    const userExists = users.find((u) => u.username === username);
    if (userExists) {
      alert("User already exists!");
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      username,
      password: hashedPassword,
    };

    localStorage.setItem(
      "users",
      JSON.stringify([...users, newUser])
    );

    alert("Registered successfully!");
    goToLogin();
  };

  return (
    <div className="auth-container">
      <h2>New Access ID</h2>
      <p style={{ marginBottom: '30px', color: '#94a3b8' }}>Create your credentials</p>

      <input
        type="text"
        placeholder="Choose Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />

      <div className="password-wrapper">
        <input
          type={showPassword ? "text" : "password"}
          placeholder="Set Password"
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

      <button className="primary-btn w-full" onClick={handleRegister}>Generate ID</button>

      <p className="mt-4" style={{ fontSize: '0.9rem', color: '#64748b' }}>
        Already authorized?{" "}
        <span className="link" onClick={goToLogin} style={{ color: '#06b6d4', cursor: 'pointer' }}>
          Login
        </span>
      </p>
    </div>
  );
}

export default Register;