// server.js
const express = require('express');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const os = require('os');
const pdfParse = require('pdf-parse');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// ============ Ensure uploads dir (temp in serverless) ============
const UPLOAD_DIR = path.join(os.tmpdir(), 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ============ MongoDB ============
mongoose.connect(
  process.env.MONGO_URI || "mongodb+srv://abcd:1234@cluster0.k4abt9h.mongodb.net/studymate",
  { useNewUrlParser: true, useUnifiedTopology: true }
).then(() => console.log("✅ MongoDB Connected"))
 .catch(err => console.error("❌ MongoDB Error:", err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }, // plain text (insecure, replace with bcrypt in prod)
  isVerified: { type: Boolean, default: false },
  otp: { type: String },
  otpExpiry: { type: Date }
});

const chatSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  messages: [
    {
      role: { type: String, enum: ["user", "assistant"], required: true },
      content: { type: String, required: true }
    }
  ],
  files: [
    {
      originalName: String,
      storedName: String,
      mimeType: String,
      size: Number,
      path: String
    }
  ],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Chat = mongoose.model("Chat", chatSchema);

// ============ Gmail Transporter ============
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "adepusanjay444@gmail.com",
    pass: "lrnesuqvssiognej", // App Password
  }
});

// ============ Gemini Setup ============
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || 'AIzaSyBxfK1fAJjzJImC6VheREpSNxl-JbVeb6g';
const MODEL = 'gemini-2.0-flash';

// -------- Multer config (disk storage in /tmp/uploads) --------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safeName = `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`;
    cb(null, safeName);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
});

// -------- CORS config --------
const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://el-front-umber.vercel.app',
];
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);

app.use(express.json());

// ===== Helpers =====
const toGeminiRole = (role) => (role === 'assistant' ? 'model' : 'user');
function chunkText(str, chunkSize = 12000) {
  const chunks = [];
  for (let i = 0; i < str.length; i += chunkSize) {
    chunks.push(str.slice(i, i + chunkSize));
  }
  return chunks;
}

async function callGemini(model, { systemText, contents }) {
  const body = {
    system_instruction: systemText ? { parts: [{ text: systemText }] } : undefined,
    contents,
  };

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-goog-api-key': GEMINI_API_KEY },
      body: JSON.stringify(body),
    }
  );

  const data = await response.json();
  if (!response.ok) {
    throw Object.assign(new Error(data.error?.message || 'Gemini API error'), { raw: data });
  }
  return data;
}

function buildContents({ messages, pdfContexts }) {
  const contents = [];
  for (const m of messages || []) {
    contents.push({ role: toGeminiRole(m.role), parts: [{ text: m.content }] });
  }
  if (pdfContexts?.length > 0) {
    for (const ctx of pdfContexts) {
      contents.push({ role: 'user', parts: [{ text: `# SOURCE: ${ctx.filename}\n${ctx.text}` }] });
    }
  }
  return contents;
}

// ===== Middleware =====
const authMiddleware = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// ===== Auth Routes =====
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "username, email, password required" });

    const exist = await User.findOne({ $or: [{ username }, { email }] });
    if (exist) return res.status(400).json({ error: "User already exists" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const user = new User({ username, email, password, otp, otpExpiry: new Date(Date.now() + 10 * 60000) });
    await user.save();

    await transporter.sendMail({
      from: `"Chat App" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: "Verify your account - OTP",
      text: `Your OTP is ${otp}. It will expire in 10 minutes.`
    });

    res.json({ message: "User registered. Check email for OTP." });
  } catch {
    res.status(400).json({ error: "Registration failed" });
  }
});

app.post("/api/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });
  if (user.isVerified) return res.json({ message: "Already verified" });
  if (user.otp !== otp || user.otpExpiry < new Date()) return res.status(400).json({ error: "Invalid/expired OTP" });

  user.isVerified = true;
  user.otp = null;
  user.otpExpiry = null;
  await user.save();

  res.json({ message: "Email verified successfully!" });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "Invalid email or password" });
  if (!user.isVerified) return res.status(403).json({ error: "Email not verified" });
  if (user.password !== password) return res.status(400).json({ error: "Invalid email or password" });

  const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, username: user.username });
});

// ===== Chat Route =====
app.post('/api/chat', authMiddleware, upload.any(), async (req, res) => {
  try {
    let messages = [];
    if (req.body?.messages) {
      try { messages = JSON.parse(req.body.messages); } catch {}
    }

    const uploadedFilesMeta = [];
    const pdfContexts = [];

    if (req.files?.length > 0) {
      for (const f of req.files) {
        uploadedFilesMeta.push({
          originalName: f.originalname,
          storedName: f.filename,
          mimeType: f.mimetype,
          size: f.size,
          path: f.path
        });

        if (f.mimetype === 'application/pdf') {
          const data = await pdfParse(fs.readFileSync(f.path));
          if (data?.text) pdfContexts.push({ filename: f.originalname, text: data.text });
        }
      }
    }

    const contents = buildContents({ messages, pdfContexts });
    const data = await callGemini(MODEL, {
      systemText: pdfContexts.length ? "Use PDF context for answers." : "You are a helpful assistant.",
      contents
    });

    const text = data?.candidates?.[0]?.content?.parts?.map(p => p.text).join("\n") || "";

    const chat = new Chat({
      userId: req.user.id,
      messages: [...messages, { role: "assistant", content: text }],
      files: uploadedFilesMeta
    });
    await chat.save();

    res.json({ ok: true, response: text, savedChatId: chat._id });
  } catch (err) {
    res.status(500).json({ error: "Chat error", details: err.message });
  }
});

// ===== Chat History =====
app.get("/api/chat-history", authMiddleware, async (req, res) => {
  const chats = await Chat.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(chats);
});

// ===== Health =====
app.get('/api/health', (req, res) => res.json({ status: 'OK' }));

// ===== Start =====
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`Uploads directory: ${UPLOAD_DIR}`);
});
