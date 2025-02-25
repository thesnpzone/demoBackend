// server.js
const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

dotenv.config();
const app = express();
app.use(express.json());
app.use(cookieParser());

// Allow frontend from localhost to communicate with backend
app.use(cors({ origin: "http://localhost:3000", credentials: true }));

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected successfully"))
.catch((err) => console.log("MongoDB connection error:", err));

// Mongoose model for Operational Admin
const operationalAdminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
});
const OperationalAdmin = mongoose.model("OperationalAdmin", operationalAdminSchema);

// Function to generate a random password
const generateRandomPassword = () => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length: 16 }, () => chars.charAt(Math.floor(Math.random() * chars.length))).join('');
};

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_PORT == "465",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// Route to register an Operational Admin
app.post("/api/operational-admin/register", async (req, res) => {
  const { name, email } = req.body;
  const existingAdmin = await OperationalAdmin.findOne({ email });
  if (existingAdmin) {
    return res.status(400).json({ message: "Email is already registered" });
  }
  const operationalAdmin = new OperationalAdmin({ name, email });
  await operationalAdmin.save();
  res.status(201).json({ message: "Operational Admin registered successfully", operationalAdmin });
});

// Route to send password via email
app.post("/api/operational-admin/send-password", async (req, res) => {
  const { email } = req.body;
  const admin = await OperationalAdmin.findOne({ email });
  if (!admin) {
    return res.status(400).json({ message: "Email is not registered" });
  }
  const password = generateRandomPassword();
  const hashedPassword = await bcrypt.hash(password, 10);
  admin.password = hashedPassword;
  await admin.save();
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your Login Password",
    text: `Your login password is: ${password}`,
  };
  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      return res.status(500).json({ message: "Error sending email" });
    }
    res.status(200).json({ message: "Password sent to your email" });
  });
});

// Login Route
app.post("/api/operational-admin/login", async (req, res) => {
  const { email, password } = req.body;
  const admin = await OperationalAdmin.findOne({ email });
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    return res.status(400).json({ message: "Invalid email or password" });
  }
  const token = jwt.sign({ id: admin._id, email: admin.email }, process.env.JWT_SECRET, { expiresIn: "15h" });
  res.cookie("OperationalAdminToken", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.status(200).json({ message: "Login successful", token, admin: { name: admin.name, email: admin.email } });
});

// Dashboard Route
app.get("/api/operational-admin/dashboard", (req, res) => {
  const token = req.cookies.OperationalAdminToken;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized access" });
  }
  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Unauthorized access" });
    }
    const admin = await OperationalAdmin.findById(decoded.id);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    res.status(200).json({ name: admin.name, email: admin.email, token });
  });
});

// Logout Route
app.post("/api/operational-admin/logout", (req, res) => {
  res.clearCookie("OperationalAdminToken", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.status(200).json({ message: "Logged out successfully" });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port http://localhost:${PORT}`));
