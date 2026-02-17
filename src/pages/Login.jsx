import { useState } from "react";
import bcrypt from "bcryptjs";

function Login({ onLogin, goToRegister }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const logActivity = (user, action) => {
    const logs = JSON.parse(localStorage.getItem("activityLogs")) || [];

    const newLog = {
      username: user,
      action,
      time: new Date().toLocaleString(),
    };

    localStorage.setItem(
      "activityLogs",
      JSON.stringify([newLog, ...logs])
    );
  };

  const handleLogin = async () => {
    const users = JSON.parse(localStorage.getItem("users")) || [];

    if (username === "admin" && password === "1234") {
      localStorage.setItem("role", "admin");
      localStorage.setItem("currentUser", "admin");
      logActivity("admin", "Logged In");
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
      logActivity(username, "Logged In");
      onLogin("user");
    } else {
      alert("Invalid credentials!");
    }
  };

  return (
    <div style={{ textAlign: "center", marginTop: "100px" }}>
      <h2>Cyber Security Login</h2>

      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <br /><br />

      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <br /><br />

      <button onClick={handleLogin}>Login</button>

      <p style={{ marginTop: "20px" }}>
        New user?{" "}
        <span
          onClick={goToRegister}
          style={{ color: "#00ffcc", cursor: "pointer" }}
        >
          Register here
        </span>
      </p>
    </div>
  );
}

export default Login;