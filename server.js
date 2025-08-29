// server.js (drop-in)
// -------------------------------------------------------------
// Core deps
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

// --------- CORS ---------
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

// --------- Upload dir (serverless-friendly tmp) ---------
const UPLOAD_DIR = path.join(os.tmpdir(), 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// --------- Multer for PDFs (only used by /api/chat if you send files) ---------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files are allowed'), false);
  },
});

// --------- MongoDB ---------
mongoose
  .connect(process.env.MONGO_URI || "mongodb+srv://abcd:1234@cluster0.k4abt9h.mongodb.net/studymate")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email:    { type: String, unique: true, required: true },
  password: { type: String, required: true }, // plain (per your request)
  isVerified: { type: Boolean, default: false },
  otp: { type: String },
  otpExpiry: { type: Date }
}, { timestamps: true });

const chatSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, default: "New Chat" },
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
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const Chat = mongoose.model("Chat", chatSchema);

// --------- Mailer (Gmail App Password) ---------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "adepusanjay444@gmail.com",
    pass: "lrnesuqvssiognej", // App Password
  }
});

// --------- Gemini Setup (Do NOT change chat logic) ---------
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || 'AIzaSyBxfK1fAJjzJImC6VheREpSNxl-JbVeb6g';
const MODEL = 'gemini-2.0-flash';

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
    const status = response.status || 500;
    throw Object.assign(new Error(details), { status, raw: data });
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

// ===================================================================
// 🔐 AUTH (only for history; /api/chat remains public)
// ===================================================================

// Generate OTP (simple 6-digit)
function genOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, requireOtp = false } = req.body || {};
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'username, email, password required' });
    }

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.status(409).json({ error: 'User already exists' });

    const user = new User({ username, email, password });

    if (requireOtp) {
      const otp = genOTP();
      user.otp = otp;
      user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 min
      await transporter.sendMail({
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP is ${otp}. It expires in 10 minutes.`,
      });
    } else {
      user.isVerified = true;
    }

    await user.save();

    // issue token anyway; frontend can block until verify if you want
    const token = jwt.sign({ uid: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      ok: true,
      token,
      user: { id: user._id, username, email, isVerified: user.isVerified }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'register_failed' });
  }
});

// Verify OTP
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { email, otp } = req.body || {};
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    if (!user.otp || !user.otpExpiry) return res.status(400).json({ error: 'no_otp_requested' });
    if (new Date() > user.otpExpiry) return res.status(400).json({ error: 'otp_expired' });
    if (otp !== user.otp) return res.status(400).json({ error: 'otp_invalid' });

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    const token = jwt.sign({ uid: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token, user: { id: user._id, username: user.username, email: user.email, isVerified: true } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'verify_failed' });
  }
});

// Login (plain text)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body || {};
    if (!emailOrUsername || !password) {
      return res.status(400).json({ error: 'emailOrUsername & password required' });
    }
    const user = await User.findOne({
      $or: [{ email: emailOrUsername }, { username: emailOrUsername }]
    });
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    const token = jwt.sign({ uid: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token, user: { id: user._id, username: user.username, email: user.email, isVerified: user.isVerified } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'login_failed' });
  }
});

// Helper: verify token (used ONLY for history APIs)
function requireAuth(req, res, next) {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'no_token' });
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.uid;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'token_invalid' });
  }
}

// ===================================================================
// 💬 Chat endpoint (UNCHANGED logic, public, no auth needed)
// ===================================================================
app.post('/api/chat', upload.array('files', 10), async (req, res) => {
  try {
    const isMultipart = req.headers['content-type']?.includes('multipart/form-data');

    // 1) messages
    let messages = [];
    if (isMultipart) {
      const raw = req.body?.messages;
      if (raw) {
        try {
          messages = JSON.parse(raw);
        } catch {
          return res.status(400).json({ error: 'Invalid JSON in "messages" field' });
        }
      } else {
        messages = [];
      }
    } else {
      messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    }

    // 2) PDFs
    let pdfContexts = [];
    if (isMultipart && req.files && req.files.length > 0) {
      const parsed = await Promise.all(
        req.files.map(async (file) => {
          const data = await pdfParse(file.buffer);
          return {
            filename: file.originalname || 'unnamed.pdf',
            text: data.text || '',
          };
        })
      );
      pdfContexts = parsed.filter((p) => p.text && p.text.trim().length > 0);
    }

    // 3) system
    const systemText =
      pdfContexts.length > 0
        ? [
            'You are a helpful assistant.',
            'Use ONLY the provided PDF context to answer when possible.',
            'If there are multiple PDFs:',
            '- One may contain questions; others may contain reference material.',
            '- Answer each question strictly using the reference PDFs. If information is missing, say what is missing.',
            'Cite the source PDF names inline like [source: filename.pdf] when helpful.',
            'If something is not in the PDFs, respond briefly and say it is not present in the provided documents.',
          ].join('\n')
        : 'You are a helpful assistant. No documents are provided; answer normally.';

    // 4) contents
    const contents = buildContents({ messages, pdfContexts });

    // 5) call model
    const data = await callGemini(MODEL, { systemText, contents });

    // 6) text out
    const text =
      data?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('\n') ||
      data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      '';

    res.json({
      ok: true,
      groundedInPdfs: pdfContexts.length > 0,
      usedSources: pdfContexts.map((p) => p.filename),
      response: text,
      raw: data,
    });
  } catch (error) {
    console.error('Gemini Chat Error:', error.raw || error);
    res
      .status(error.status || 500)
      .json({ error: 'Gemini Chat Error', details: error.message });
  }
});

// ===================================================================
// 🗂️ Chat history APIs (need Bearer token; DO NOT affect /api/chat)
// ===================================================================

// 1) Create a chat session (optional title; you can create first then push messages)
app.post('/api/history/chats', requireAuth, async (req, res) => {
  try {
    const { title = 'New Chat', firstMessage } = req.body || {};
    const chat = new Chat({
      userId: req.userId,
      title,
      messages: firstMessage ? [firstMessage] : [],
    });
    await chat.save();
    res.json({ ok: true, chatId: chat._id, chat });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'create_chat_failed' });
  }
});

// 2) List chats for user (latest first)
app.get('/api/history/chats', requireAuth, async (req, res) => {
  try {
    const chats = await Chat.find({ userId: req.userId })
      .select('_id title createdAt updatedAt')
      .sort({ updatedAt: -1 });
    res.json({ ok: true, chats });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'list_chats_failed' });
  }
});

// 3) Get single chat (messages)
app.get('/api/history/chats/:id', requireAuth, async (req, res) => {
  try {
    const chat = await Chat.findOne({ _id: req.params.id, userId: req.userId });
    if (!chat) return res.status(404).json({ error: 'chat_not_found' });
    res.json({ ok: true, chat });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'get_chat_failed' });
  }
});

// 4) Append messages to a chat (after you get /api/chat response)
app.post('/api/history/chats/:id/messages', requireAuth, async (req, res) => {
  try {
    const { messages = [] } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0)
      return res.status(400).json({ error: 'messages_required' });

    const chat = await Chat.findOne({ _id: req.params.id, userId: req.userId });
    if (!chat) return res.status(404).json({ error: 'chat_not_found' });

    // Push valid messages only
    for (const m of messages) {
      if (!m.role || !m.content) continue;
      chat.messages.push({ role: m.role, content: m.content });
    }
    await chat.save();
    res.json({ ok: true, chat });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'append_failed' });
  }
});

// 5) Rename chat
app.patch('/api/history/chats/:id', requireAuth, async (req, res) => {
  try {
    const { title } = req.body || {};
    const chat = await Chat.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { $set: { title: title || 'Untitled' } },
      { new: true }
    );
    if (!chat) return res.status(404).json({ error: 'chat_not_found' });
    res.json({ ok: true, chat });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'rename_failed' });
  }
});

// 6) Delete one chat
app.delete('/api/history/chats/:id', requireAuth, async (req, res) => {
  try {
    const r = await Chat.deleteOne({ _id: req.params.id, userId: req.userId });
    if (!r.deletedCount) return res.status(404).json({ error: 'chat_not_found' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'delete_failed' });
  }
});

// 7) Delete all chats (danger)
app.delete('/api/history/chats', requireAuth, async (req, res) => {
  try {
    await Chat.deleteMany({ userId: req.userId });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'delete_all_failed' });
  }
});

// (Optional) attach files metadata to a chat (store to disk)
const diskUpload = multer({ dest: UPLOAD_DIR });
app.post('/api/history/chats/:id/files', requireAuth, diskUpload.array('files', 10), async (req, res) => {
  try {
    const chat = await Chat.findOne({ _id: req.params.id, userId: req.userId });
    if (!chat) return res.status(404).json({ error: 'chat_not_found' });

    for (const f of req.files || []) {
      chat.files.push({
        originalName: f.originalname,
        storedName: f.filename,
        mimeType: f.mimetype,
        size: f.size,
        path: f.path,
      });
    }
    await chat.save();
    res.json({ ok: true, files: chat.files });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'attach_failed' });
  }
});

// ===================================================================
// Health
// ===================================================================
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Server is running',
    environment: process.env.NODE_ENV || 'development',
  });
});

// ===================================================================
// Start
// ===================================================================
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 CORS allowed from: ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(`🔍 Health check: http://localhost:${PORT}/api/health`);
  console.log(`💬 Chat endpoint (public): http://localhost:${PORT}/api/chat`);
});

module.exports = app;