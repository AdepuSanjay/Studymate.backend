// server.js
const express = require('express');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const pdfParse = require('pdf-parse');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// ============ Ensure uploads dir ============
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ============ MongoDB ============
mongoose.connect(
  process.env.MONGO_URI || "mongodb+srv://abcd:1234@cluster0.k4abt9h.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
  { useNewUrlParser: true, useUnifiedTopology: true }
).then(() => console.log("✅ MongoDB Connected"))
 .catch(err => console.error("❌ MongoDB Error:", err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  // NOTE: storing plain text password (insecure). Replace with hashing in production.
  password: { type: String, required: true },
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
  // optional: store uploaded file metadata with this chat
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
        pass: "lrnesuqvssiognej",
  }
});

// ============ Gemini Setup ============
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || 'AIzaSyBxfK1fAJjzJImC6VheREpSNxl-JbVeb6g';
const MODEL = 'gemini-2.0-flash';

// -------- Multer config for ANY file uploads (store on disk) --------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // unique name: timestamp-originalname
    const safeName = `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`;
    cb(null, safeName);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB per file (adjust if needed)
  // no fileFilter -> accept all types
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
  let i = 0;
  while (i < str.length) {
    chunks.push(str.slice(i, i + chunkSize));
    i += chunkSize;
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
      headers: {
        'Content-Type': 'application/json',
        'X-goog-api-key': GEMINI_API_KEY,
      },
      body: JSON.stringify(body),
    }
  );

  const data = await response.json();
  if (!response.ok) {
    const details =
      data.error?.message ||
      data.promptFeedback?.blockReason ||
      data.candidates?.[0]?.finishReason ||
      'Unknown error';
    throw Object.assign(new Error(details), { status: response.status || 500, raw: data });
  }
  return data;
}

function buildContents({ messages, pdfContexts }) {
  const contents = [];
  for (const m of messages || []) {
    contents.push({
      role: toGeminiRole(m.role),
      parts: [{ text: m.content }],
    });
  }
  if (pdfContexts && pdfContexts.length > 0) {
    for (const ctx of pdfContexts) {
      const header = `# SOURCE: ${ctx.filename}\n(Extracted text below)`;
      contents.push({ role: 'user', parts: [{ text: header }] });
      const chunks = chunkText(ctx.text);
      const maxChunks = Math.min(chunks.length, 10);
      for (let i = 0; i < maxChunks; i++) {
        contents.push({
          role: 'user',
          parts: [{ text: `[[${ctx.filename} :: part ${i + 1}/${maxChunks}]]\n${chunks[i]}` }],
        });
      }
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
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// ===== Auth Routes =====
// Register (stores plain password because bcrypt was requested to be removed)
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "username, email, password required" });

    // check existing
    const exist = await User.findOne({ $or: [{ username }, { email }] });
    if (exist) return res.status(400).json({ error: "User with username or email already exists" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const user = new User({
      username,
      email,
      password, // plain text stored (insecure) — replace with hashing in future
      otp,
      otpExpiry: new Date(Date.now() + 10 * 60 * 1000)
    });
    await user.save();

    // send OTP email
    await transporter.sendMail({
      from: `"Chat App" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: "Verify your account - OTP",
      text: `Your OTP is ${otp}. It will expire in 10 minutes.`
    });

    res.json({ message: "User registered. Check email for OTP." });
  } catch (err) {
    console.error('register error', err);
    res.status(400).json({ error: "User already exists or invalid data" });
  }
});

app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: "email and otp required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });
    if (user.isVerified) return res.json({ message: "Already verified" });
    if (user.otp !== otp || user.otpExpiry < new Date()) return res.status(400).json({ error: "Invalid or expired OTP" });

    user.isVerified = true;
    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    res.json({ message: "Email verified successfully!" });
  } catch (err) {
    console.error('verify-otp error', err);
    res.status(500).json({ error: "OTP verification failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });
    if (!user.isVerified) return res.status(403).json({ error: "Email not verified" });

    // plain-text compare (insecure)
    if (user.password !== password) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, username: user.username });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ===== Chat Route with Gemini + Save (accepts any file uploads) =====
// multipart form using field 'messages' (JSON string) and file fields (any names)
app.post('/api/chat', authMiddleware, upload.any(), async (req, res) => {
  try {
    // messages may be in body.messages (JSON) or in JSON body
    let messages = [];
    if (req.is('multipart/form-data')) {
      if (req.body?.messages) {
        try {
          messages = JSON.parse(req.body.messages);
        } catch (e) {
          return res.status(400).json({ error: 'Invalid JSON in "messages" field' });
        }
      } else {
        messages = [];
      }
    } else {
      messages = Array.isArray(req.body?.messages) ? req.body.messages : (req.body.messages || []);
    }

    // process uploaded files: build metadata array and parse PDFs
    const uploadedFilesMeta = [];
    const pdfContexts = [];

    if (req.files && req.files.length > 0) {
      for (const f of req.files) {
        const meta = {
          originalName: f.originalname,
          storedName: f.filename,
          mimeType: f.mimetype,
          size: f.size,
          path: f.path
        };
        uploadedFilesMeta.push(meta);

        // If PDF, try to extract text
        if (f.mimetype === 'application/pdf') {
          try {
            const buff = fs.readFileSync(f.path);
            const data = await pdfParse(buff);
            if (data?.text && data.text.trim().length > 0) {
              pdfContexts.push({ filename: f.originalname || f.filename, text: data.text });
            }
          } catch (err) {
            console.warn(`Failed to parse PDF ${f.originalname}:`, err.message || err);
          }
        }
      }
    }

    const systemText = pdfContexts.length > 0
      ? [
        'You are a helpful assistant.',
        'Use ONLY the provided PDF context to answer when possible.',
        'Cite the source PDF names inline like [source: filename.pdf] when helpful.',
      ].join('\n')
      : 'You are a helpful assistant.';

    const contents = buildContents({ messages, pdfContexts });
    const data = await callGemini(MODEL, { systemText, contents });

    const text =
      data?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('\n') ||
      data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      '';

    // Save conversation to DB (with file metadata)
    const chat = new Chat({
      userId: req.user.id,
      messages: [
        ...messages,
        { role: "assistant", content: text }
      ],
      files: uploadedFilesMeta
    });
    await chat.save();

    res.json({
      ok: true,
      groundedInPdfs: pdfContexts.length > 0,
      usedSources: pdfContexts.map((p) => p.filename),
      response: text,
      savedChatId: chat._id
    });
  } catch (error) {
    console.error('Gemini Chat Error:', error.raw || error);
    res.status(error.status || 500).json({ error: "Chat error", details: error.message || error });
  }
});

// ===== Get Chat History =====
app.get("/api/chat-history", authMiddleware, async (req, res) => {
  try {
    const chats = await Chat.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(chats);
  } catch (err) {
    console.error('chat-history error', err);
    res.status(500).json({ error: "Failed to fetch chat history" });
  }
});

// ===== Health =====
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`Uploads directory: ${UPLOAD_DIR}`);
});
