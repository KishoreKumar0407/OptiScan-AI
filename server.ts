import "dotenv/config";
import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";
import bcrypt from "bcryptjs";

const db = new Database("optiscann.db");

// Initialize DB
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  );

  CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT,
    age INTEGER,
    gender TEXT,
    relationship TEXT,
    is_authorized BOOLEAN DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    profile_id TEXT,
    patient_name TEXT,
    data TEXT,
    previous_report_data TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(profile_id) REFERENCES profiles(id)
  );

  CREATE TABLE IF NOT EXISTS appointments (
    id TEXT PRIMARY KEY,
    profile_id TEXT,
    patient_name TEXT,
    report_id TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(profile_id) REFERENCES profiles(id)
  );
`);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json({ limit: '50mb' }));

  // Auth Routes
  app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;
    try {
      const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
      if (existingUser) {
        return res.status(400).json({ success: false, message: "Username already exists" });
      }

      const id = Math.random().toString(36).substr(2, 9);
      const hashedPassword = await bcrypt.hash(password, 10);
      db.prepare("INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)").run(id, username, hashedPassword, username === 'admin' ? 'admin' : 'user');
      
      // Auto-create 'Self' profile for new user
      const profileId = Math.random().toString(36).substr(2, 9);
      db.prepare("INSERT INTO profiles (id, user_id, name, age, gender, relationship, is_authorized) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(profileId, id, username, 25, 'Male', 'Self', 1);

      res.json({ success: true, message: "User registered successfully" });
    } catch (error) {
      res.status(500).json({ success: false, message: "Registration failed" });
    }
  });

  app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    try {
      const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as any;
      if (!user) {
        return res.status(401).json({ success: false, message: "Invalid credentials" });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ success: false, message: "Invalid credentials" });
      }

      // Don't send password back
      const { password: _, ...userWithoutPassword } = user;
      res.json({ success: true, user: userWithoutPassword });
    } catch (error) {
      res.status(500).json({ success: false, message: "Login failed" });
    }
  });

  // Profile Routes
  app.get("/api/profiles/:userId", (req, res) => {
    const profiles = db.prepare("SELECT * FROM profiles WHERE user_id = ?").all(req.params.userId);
    res.json(profiles);
  });

  app.post("/api/profiles", (req, res) => {
    const { id, userId, name, age, gender, relationship } = req.body;
    db.prepare("INSERT INTO profiles (id, user_id, name, age, gender, relationship, is_authorized) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id, userId, name, age, gender, relationship, 1); // Authorized by default as requested
    res.json({ success: true });
  });

  app.post("/api/profiles/authorize", (req, res) => {
    const { profileId, isAuthorized } = req.body;
    db.prepare("UPDATE profiles SET is_authorized = ? WHERE id = ?").run(isAuthorized ? 1 : 0, profileId);
    res.json({ success: true });
  });

  app.get("/api/profiles/all", (req, res) => {
    const profiles = db.prepare("SELECT * FROM profiles").all();
    res.json(profiles);
  });

  app.get("/api/reports/profile/all", (req, res) => {
    const reports = db.prepare("SELECT * FROM reports ORDER BY created_at DESC").all();
    res.json(reports);
  });

  // API Routes
  app.post("/api/reports", (req, res) => {
    const { id, profileId, patientName, data, previousReportData } = req.body;
    const stmt = db.prepare("INSERT INTO reports (id, profile_id, patient_name, data, previous_report_data) VALUES (?, ?, ?, ?, ?)");
    stmt.run(id, profileId, patientName, JSON.stringify(data), previousReportData ? JSON.stringify(previousReportData) : null);
    res.json({ success: true });
  });

  app.get("/api/reports/profile/:profileId", (req, res) => {
    const reports = db.prepare("SELECT * FROM reports WHERE profile_id = ? ORDER BY created_at DESC").all(req.params.profileId);
    res.json(reports.map((r: any) => ({ ...r, data: JSON.parse(r.data), previous_report_data: r.previous_report_data ? JSON.parse(r.previous_report_data) : null })));
  });

  app.post("/api/appointments", (req, res) => {
    const { profileId, patientName, reportId } = req.body;
    const id = Math.random().toString(36).substr(2, 9);
    try {
      db.prepare("INSERT INTO appointments (id, profile_id, patient_name, report_id, status) VALUES (?, ?, ?, ?, ?)").run(id, profileId, patientName, reportId, 'pending');
      res.json({ success: true, id });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  app.get("/api/appointments/all", (req, res) => {
    const appointments = db.prepare("SELECT * FROM appointments ORDER BY created_at DESC").all();
    res.json(appointments);
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(process.cwd(), "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(process.cwd(), "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
