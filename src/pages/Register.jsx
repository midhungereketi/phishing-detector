import { useState } from "react";
import bcrypt from "bcryptjs";

function Register({ goToLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleRegister = async () => {
    if (!username || !password) {
      alert("Please fill all fields");
      return;
    }

    const users = JSON.parse(localStorage.getItem("users")) || [];

    const userExists = users.find((u) => u.username === username);
    if (userExists) {
      alert("Username already exists!");
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = { username, password: hashedPassword };

    const updatedUsers = [...users, newUser];
    localStorage.setItem("users", JSON.stringify(updatedUsers));

    alert("Registration successful!");
    goToLogin();
  };

  return (
    <div style={{ textAlign: "center", marginTop: "100px" }}>
      <h2>User Registration</h2>

      <input
        type="text"
        placeholder="Choose Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <br /><br />

      <input
        type="password"
        placeholder="Choose Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <br /><br />

      <button onClick={handleRegister}>Register</button>

      <p style={{ marginTop: "20px" }}>
        Already have account?{" "}
        <span
          onClick={goToLogin}
          style={{ color: "#00ffcc", cursor: "pointer" }}
        >
          Login here
        </span>
      </p>
    </div>
  );
}

export default Register;