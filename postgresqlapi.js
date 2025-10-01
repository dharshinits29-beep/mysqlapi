require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 5001;


app.use(cors());
app.use(bodyParser.json());


const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: 5432, 
});

pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => {
    console.error("❌ PostgreSQL connection error:", err);
    process.exit(1);
  });


(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) NOT NULL,
      password VARCHAR(255) NOT NULL
    )
  `);
  console.log("✅ Users table ready");
})();


app.post("/register", async (req, res) => {
  console.log("Register requset recieved");
  const { username, email, password } = req.body;
  console.log("Requst body:",req.body);
  if (!username || !email || !password) return res.status(400).json({ message: "All fields are required" });

  try {
    console.log("checking if username exist");
    const existing = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
    if (existing.rows.length > 0) return res.status(400).json({ message: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 8);
    console.log("inserting user database");
    await pool.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [username, email, hashedPassword]);
    console.log(`new user registered:${username}`);

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.post("/login", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ message: "All fields required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
    if (result.rows.length === 0) return res.status(400).json({ message: "Invalid username" });

    const user = result.rows[0];
    if (user.email !== email) return res.status(400).json({ message: "Invalid email" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, process.env.JWT_SECRET);
    console.log("Generrated JWT token:",token);

    const { password: _, ...userWithoutPassword } = user;
    res.json({ message: "Login successful", user: userWithoutPassword, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/dashboard/add-users", async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 5;
  const offset = (page - 1) * limit;

  try {
    const usersResult = await pool.query("SELECT id, username, email FROM users ORDER BY id LIMIT $1 OFFSET $2", [limit, offset]);
    const countResult = await pool.query("SELECT COUNT(*) AS total FROM users");
    const totalUsers = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(totalUsers / limit);

    res.json({ page, limit, totalUsers, totalPages, users: usersResult.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.post("/dashboard/add-user", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ message: "All fields required" });

  try {
    const existing = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
    if (existing.rows.length > 0) return res.status(400).json({ message: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 8);
    await pool.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [username, email, hashedPassword]);

    res.status(201).json({ message: "Dashboard user added successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.put("/users/:username", async (req, res) => {
  const { username } = req.params;
  const { newUsername, newEmail } = req.body;

  if (!newUsername || !newEmail) return res.status(400).json({ message: "Both username and email required" });

  try {
    const existing = await pool.query("SELECT id FROM users WHERE username=$1", [newUsername]);
    if (existing.rows.length > 0 && newUsername !== username) return res.status(400).json({ message: "Username exists" });

    const result = await pool.query("UPDATE users SET username=$1, email=$2 WHERE username=$3 RETURNING *", [newUsername, newEmail, username]);
    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });

    const { password: _, ...userWithoutPassword } = result.rows[0];
    res.json({ message: "User updated successfully", user: userWithoutPassword });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.delete("/users/:username", async (req, res) => {
  const { username } = req.params;
  try {
    const result = await pool.query("DELETE FROM users WHERE username=$1 RETURNING *", [username]);
    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.listen(PORT, () => {
  console.log(`🚀 PostgreSQL API running at http://localhost:${PORT}`);
});
