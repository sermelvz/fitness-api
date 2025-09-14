// server.js
import express from "express";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pkg;
const app = express();

app.use(cors());
app.use(express.json());

// --- DB Connection ---
const pool = new Pool({
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
  ssl: { rejectUnauthorized: false }
});

// --- Helpers ---
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "No token" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Invalid token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
}

// --- AUTH ROUTES ---
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password, displayName } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash, display_name)
       VALUES ($1, $2, $3, $4) RETURNING id, username, email, display_name`,
      [username, email, hashed, displayName || username]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query(`SELECT * FROM users WHERE username=$1`, [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(user);
    res.json({ token, username: user.username, displayName: user.display_name });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

// --- PROFILE ---
// Get Profile
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    // Base user info
    const userResult = await pool.query(
      `SELECT id, username, email, display_name AS "displayName"
       FROM users WHERE id=$1`,
      [req.user.id]
    );

    // Extra profile info
    const profileResult = await pool.query(
      `SELECT 
         first_name AS "firstName",
         last_name AS "lastName",
         age,
         weight_kg AS "weightKg",
         height_cm AS "heightCm",
         bio,
         profile_pic_url AS "profilePicUrl"
       FROM profiles WHERE user_id=$1`,
      [req.user.id]
    );

    res.json({
      ...userResult.rows[0],
      ...profileResult.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch profile" });
  }
});

// Update Profile
app.put("/api/profile", authMiddleware, async (req, res) => {
  const { firstName, lastName, email, age, weightKg, profilePicUrl, heightCm } = req.body;

  try {
    // 1. Update email if provided
    if (email) {
      await pool.query(`UPDATE users SET email=$1 WHERE id=$2`, [email, req.user.id]);
    }

    // 2. Fetch current profile values
    const existing = await pool.query(
      `SELECT * FROM profiles WHERE user_id=$1`,
      [req.user.id]
    );
    const current = existing.rows[0] || {};

    // 3. Merge incoming with existing
    const updated = {
      firstName: firstName ?? current.first_name,
      lastName: lastName ?? current.last_name,
      age: age ?? current.age,
      weightKg: weightKg ?? current.weight_kg,
      profilePicUrl: profilePicUrl ?? current.profile_pic_url,
      heightCm: heightCm ?? current.height_cm
    };

    // 4. Insert or update
    await pool.query(
      `INSERT INTO profiles (user_id, first_name, last_name, age, weight_kg, profile_pic_url, height_cm)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (user_id) DO UPDATE
       SET first_name=$2, last_name=$3, age=$4, weight_kg=$5, profile_pic_url=$6, height_cm=$7`,
      [req.user.id, updated.firstName, updated.lastName, updated.age, updated.weightKg, updated.profilePicUrl, updated.heightCm]
    );

    // 5. Save BMI if weight & height present
    if (updated.weightKg && updated.heightCm) {
    const heightM = updated.heightCm / 100;
    const bmi = updated.weightKg / (heightM * heightM);
    await pool.query(
    `INSERT INTO bmi_history (user_id, bmi) VALUES ($1,$2)`,
    [req.user.id, bmi]
  );
}

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Profile update failed" });
  }
});

// --- WORKOUTS ---
app.get("/api/workout", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM workouts WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch workouts" });
  }
});

app.post("/api/workout", authMiddleware, async (req, res) => {
  const { exerciseName, sets, reps, weightKg } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO workouts (user_id, exercise_name, sets, reps, weight_kg)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.id, exerciseName, sets, reps, weightKg]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to add workout" });
  }
});

// --- NUTRITION ---
app.get("/api/nutrition", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM nutrition WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch meals" });
  }
});

app.post("/api/nutrition", authMiddleware, async (req, res) => {
  const { name, mealType, proteinGrams, fatGrams } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO nutrition (user_id, name, meal_type, protein_grams, fat_grams)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.id, name, mealType, proteinGrams, fatGrams]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to add meal" });
  }
});

// --- CUSTOM EXERCISES ---
app.get("/api/customexercise", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM custom_exercises WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch custom exercises" });
  }
});

app.post("/api/customexercise", authMiddleware, async (req, res) => {
  const { name, category, duration, notes } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO custom_exercises (user_id, name, category, duration, notes)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.id, name, category, duration, notes]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to add custom exercise" });
  }
});

// --- PRESET EXERCISES ---
app.get("/api/presets", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM preset_exercises ORDER BY id ASC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch presets" });
  }
});

app.post("/api/presets/complete", authMiddleware, async (req, res) => {
  const { presetId } = req.body;
  try {
    const preset = await pool.query("SELECT * FROM preset_exercises WHERE id=$1", [presetId]);
    if (!preset.rows[0]) return res.status(404).json({ message: "Preset not found" });

    const p = preset.rows[0];

    // Log into workouts as a completed preset
    const result = await pool.query(
      `INSERT INTO workouts (user_id, exercise_name, sets, reps, weight_kg, created_at)
       VALUES ($1,$2,1,$3,0,NOW()) RETURNING *`,
      [req.user.id, p.name, p.duration]
    );

    res.json({ success: true, workout: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to complete preset" });
  }
});

// --- PROGRESS ---
app.get("/api/progress", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT created_at, sets, reps, weight_kg
       FROM workouts
       WHERE user_id=$1
       AND created_at >= NOW() - INTERVAL '7 days'`,
      [req.user.id]
    );

    const days = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
    const calories = [0,0,0,0,0,0,0];
    const workoutMinutes = [0,0,0,0,0,0,0];

    result.rows.forEach(w => {
      const dayIndex = new Date(w.created_at).getDay();
      const mappedIndex = (dayIndex + 6) % 7;

      const minutes = (w.sets || 0) * 2;
      workoutMinutes[mappedIndex] += minutes;

      const cal = (w.reps || 0) * (w.sets || 0) * (w.weight_kg || 10) * 0.1;
      calories[mappedIndex] += cal;
    });

    const totalMinutes = workoutMinutes.reduce((a,b) => a+b, 0);
    const weeklyGoal = Math.min(100, Math.round((totalMinutes / 150) * 100));

    res.json({
      labels: days,
      calories,
      workoutMinutes,
      totalCalories: calories.reduce((a,b) => a+b, 0),
      totalSteps: 0,
      weeklyGoal
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to calculate progress" });
  }
});

// --- Start Server ---
const PORT = process.env.PORT || 5068;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));