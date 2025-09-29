// server.js (drop-in)
// -------------------------------------------------------------
// Core deps
const express = require('express');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
require('dotenv').config();
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const os = require('os');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');              // for .docx
const textract = require('textract');            // for many office formats (pptx/xlsx/doc/etc.) & html/rtf
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";



const HF_API_KEY = process.env.HF_API_KEY; // e.g. hf_xxx (DO NOT commit)
const GRANITE_MODEL = process.env.GRANITE_MODEL || "ibm-granite/granite-3.3-8b-instruct";
const HF_INFERENCE_BASE = process.env.HF_INFERENCE_BASE || "https://api-inference.huggingface.co";
const HF_GRANITE_ENDPOINT = `${HF_INFERENCE_BASE}/models/${GRANITE_MODEL}`;

if (!HF_API_KEY) {
  console.warn("⚠️  HF_API_KEY is not set. /api/chat-ibm will fail until you provide it in .env");
}


// --------- CORS ---------
const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'https://connected-village-care.vercel.app',
  'https://studymate-swart.vercel.app'
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

// --------- Multer (accept ANY file field names & types) ---------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB per file
  fileFilter: (req, file, cb) => {
    // Accept all; we’ll validate/attempt extraction per type below.
    cb(null, true);
  },
});

// --------- MongoDB ---------
mongoose
  .connect(process.env.MONGO_URI || "mongodb+srv://Abcd:123@cluster0.lc6c1xt.mongodb.net/study")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: false, required: true },
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


const GEMINI_API_KEY = process.env.GEMINI_API_KEY ||'AIzaSyDb_dgJI1gxqYGD6xEW5wEiCTEJjyy6z3U';
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



async function callGeminiWithTimeout(model, { systemText, contents }, ms = 20000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), ms);

  try {
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
        signal: controller.signal,
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
  } finally {
    clearTimeout(id);
  }
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




function buildContents({ messages, pdfContexts, imageBlobs }) {
  const contents = [];

  // chat history
  for (const m of messages || []) {
    if (!m?.content) continue;
    contents.push({
      role: toGeminiRole(m.role),
      parts: [{ text: m.content }],
    });
  }

  // textual docs (pdf/docx/etc.) converted to text
  if (pdfContexts?.length) {
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

  // images as inlineData (OCR ki baduluga direct ga)
  if (imageBlobs?.length) {
    for (const img of imageBlobs) {
      contents.push({
        role: 'user',
        parts: [
          { text: `# SOURCE: ${img.filename}\nUse this image to answer. If text is present, read it.` },
          { inlineData: { mimeType: img.mimeType, data: img.base64 } },
        ],
      });
    }
  }

  return contents;
}






// ===================================================================
// 🔎 Text extraction for many file types
// ===================================================================
const extFromName = (name = '') => (name.split('.').pop() || '').toLowerCase();


// ADD THIS ↓↓↓
const isImage = (file) =>
  (file?.mimetype && file.mimetype.startsWith('image/')) ||
  ['png','jpg','jpeg','bmp','gif','tiff','webp'].includes(extFromName(file?.originalname || ''));




async function ocrImageToText(buffer) {
  try {
    const { createWorker } = await import('tesseract.js'); // dynamic to avoid cold-start cost
    const worker = await createWorker();
    try {
      const { data: { text } } = await worker.recognize(buffer);
      await worker.terminate();
      return text || '';
    } catch (e) {
      await worker.terminate();
      throw e;
    }
  } catch (e) {
    console.error('OCR error (tesseract):', e.message || e);
    return ''; // fail soft
  }
}

function textractFromBuffer(mime, buffer, ext) {
  return new Promise((resolve) => {
    // textract wants either mimetype or "path" style hints; we can hint with ext
    textract.fromBufferWithMime(mime || '', buffer, { typeOverride: ext }, (err, text) => {
      if (err) {
        console.error('textract error:', err.message || err);
        return resolve('');
      }
      resolve(text || '');
    });
  });
}

async function extractTextFromFile(file) {
  const mime = file.mimetype || '';
  const ext = extFromName(file.originalname);

  // 1) PDFs
  if (mime === 'application/pdf' || ext === 'pdf') {
    try {
      const data = await pdfParse(file.buffer);
      return data.text || '';
    } catch (e) {
      console.error('pdf-parse error:', e.message || e);
      // fallback to textract attempt
      const fallback = await textractFromBuffer(mime, file.buffer, ext);
      return fallback || '';
    }
  }

  // 2) DOCX
  if (mime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' || ext === 'docx') {
    try {
      const { value } = await mammoth.extractRawText({ buffer: file.buffer });
      return value || '';
    } catch (e) {
      console.error('mammoth error:', e.message || e);
      const fallback = await textractFromBuffer(mime, file.buffer, ext);
      return fallback || '';
    }
  }

  // 3) Plain-ish text
  if (
    mime.startsWith('text/') ||
    ['txt', 'md', 'csv', 'json', 'log'].includes(ext)
  ) {
    try {
      // Decode as UTF-8 text
      return file.buffer.toString('utf8');
    } catch {
      return '';
    }
  }

  // 4) HTML/RTF/Older Office/PPTX/XLSX/ODT/... via textract
  if (
    [
      'application/rtf',
      'text/rtf',
      'text/html',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.ms-excel',
      'application/vnd.oasis.opendocument.text',
      'application/vnd.oasis.opendocument.spreadsheet',
      'application/vnd.oasis.opendocument.presentation'
    ].includes(mime) ||
    ['rtf', 'html', 'htm', 'doc', 'ppt', 'pptx', 'xls', 'xlsx', 'odt', 'ods', 'odp'].includes(ext)
  ) {
    const text = await textractFromBuffer(mime, file.buffer, ext);
    return text || '';
  }

  // 5) Images -> OCR
  if (mime.startsWith('image/') || ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'tiff', 'webp'].includes(ext)) {
    const text = await ocrImageToText(file.buffer);
    return text || '';
  }

  // 6) Unknown -> try textract anyway
  const fallback = await textractFromBuffer(mime, file.buffer, ext);
  return fallback || '';
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
// 💬 Chat endpoint (public, no auth) — now accepts ANY file fields
// ===================================================================
app.post('/api/chat', upload.any(), async (req, res) => {
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

    // 2) Files split: images vs docs
    const incomingFiles = Array.isArray(req.files) ? req.files : [];
    const imageFiles = incomingFiles.filter(isImage);
    const docFiles   = incomingFiles.filter(f => !isImage(f));

    // 2a) docs → text extraction (existing pipeline)
    let fileContexts = [];
    if (isMultipart && docFiles.length > 0) {
      const parsed = await Promise.all(
        docFiles.map(async (file) => {
          const text = await extractTextFromFile(file);
          return {
            filename: file.originalname || 'unnamed',
            text: (text || '').trim(),
          };
        })
      );
      fileContexts = parsed.filter(p => p.text && p.text.length > 0);
    }

    // 2b) images → inlineData (NO OCR here)
    const imageBlobs = imageFiles.map(f => ({
      filename: f.originalname || 'image',
      mimeType: f.mimetype || 'image/png',
      base64: f.buffer.toString('base64'),
    }));

    // 3) system prompt
    const systemText =
      (fileContexts.length > 0 || imageBlobs.length > 0)
        ? [
            'You are a helpful assistant.',
            'You may receive text snippets and/or images as sources.',
            'Use ONLY the provided sources when possible; cite file names like [source: filename].',
            'If an image has text, read it and use it.',
            'If information is missing, say what is missing.',
          ].join('\n')
        : 'You are a helpful assistant. No documents are provided; answer normally.';

    // 4) contents
    const contents = buildContents({ messages, pdfContexts: fileContexts, imageBlobs });

    // 5) guard: nothing to send
    if (!contents || contents.length === 0) {
      return res.status(400).json({ error: 'no_input', details: 'Provide messages or files.' });
    }

    // 6) call model (with timeout)
    const data = await callGeminiWithTimeout(MODEL, { systemText, contents }, 20000);

    // 7) text out
    const text =
      data?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('\n') ||
      data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      '';

    res.json({
      ok: true,
      groundedInPdfs: fileContexts.length > 0,
      usedSources: [
        ...fileContexts.map((p) => p.filename),
        ...imageBlobs.map((i) => i.filename),
      ],
      response: text || '(No text returned)',
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


// Convert Gemini 'contents' to a single prompt for Granite-style text-generation
function contentsToPrompt({ systemText, contents }) {
  const sys = systemText ? `### System\n${systemText}\n\n` : "";
  const conv = (contents || [])
    .map((c) => {
      const role = c.role === 'model' ? 'assistant' : c.role; // gemini -> generic
      const text = (c.parts || []).map(p => p.text || "").join("\n");
      return role && text ? `**${role.toUpperCase()}**:\n${text}\n` : "";
    })
    .join("\n");
  return `${sys}${conv}\n**ASSISTANT**:\n`;
}



async function callGraniteHF({ prompt, max_new_tokens = 600, temperature = 0.2 }) {
  const resp = await fetch(HF_GRANITE_ENDPOINT, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${HF_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      inputs: prompt,
      parameters: { max_new_tokens, temperature },
      options: { wait_for_model: true, use_cache: true },
    }),
  });

  const bodyText = await resp.text();            // ← read text first
  let json = null;
  try { json = JSON.parse(bodyText); } catch {}  // ← may be plain text (e.g., 404 "Not Found")

  if (!resp.ok) {
    const msg = json?.error || bodyText || `${resp.status} ${resp.statusText}`;
    const err = new Error(`Granite HF error: ${msg}`); 
    err.status = resp.status || 500;
    err.raw = json ?? bodyText;
    throw err;
  }

  // Normalize output
  const text =
    (Array.isArray(json) && (json[0]?.generated_text || json[0]?.summary_text)) ||
    json?.generated_text || json?.text ||
    (typeof json === "string" ? json : "");

  return { raw: json ?? bodyText, text: text || "" };
}





// ===================================================================
// 💬 IBM Granite endpoint (public, no auth) — mirrors /api/chat
// ===================================================================
app.post('/api/chat-ibm', upload.any(), async (req, res) => {
  try {
    const isMultipart = req.headers['content-type']?.includes('multipart/form-data');

    // 1) messages
    let messages = [];
    if (isMultipart) {
      const raw = req.body?.messages;
      if (raw) {
        try { messages = JSON.parse(raw); }
        catch { return res.status(400).json({ error: 'Invalid JSON in "messages" field' }); }
      }
    } else {
      messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    }

    // 2) Files -> Text contexts
    let fileContexts = [];
    const incomingFiles = Array.isArray(req.files) ? req.files : [];
    if (isMultipart && incomingFiles.length > 0) {
      const parsed = await Promise.all(
        incomingFiles.map(async (file) => {
          const text = await extractTextFromFile(file);
          return {
            filename: file.originalname || 'unnamed',
            text: (text || '').trim(),
          };
        })
      );
      fileContexts = parsed.filter(p => p.text && p.text.length > 0);
    }

    // 3) system
    const systemText =
      fileContexts.length > 0
        ? [
            'You are a helpful assistant.',
            'Use ONLY the provided document context to answer when possible.',
            'If multiple files are present:',
            '- One may contain questions; others may contain reference material.',
            '- Answer strictly using the reference documents. If info is missing, say what is missing.',
            'Cite the source file names inline like [source: filename.ext] when helpful.',
            'If something is not in the documents, say it is not present there.',
          ].join('\n')
        : 'You are a helpful assistant. No documents are provided; answer normally.';

    // 4) Build Gemini-style contents (reuse your helper)
    const contents = buildContents({ messages, pdfContexts: fileContexts });

    // 5) Convert contents to Granite prompt and call Granite
    const prompt = contentsToPrompt({ systemText, contents });
    const { raw, text } = await callGraniteHF({
      prompt,
      max_new_tokens: 800,
      temperature: 0.2,
    });

    // 6) Respond in SAME shape as /api/chat
    res.json({
      ok: true,
      groundedInPdfs: fileContexts.length > 0,
      usedSources: fileContexts.map((p) => p.filename),
      response: text,
      raw,
    });
  } catch (error) {
    console.error('Granite Chat Error:', error.raw || error);
    res
      .status(error.status || 500)
      .json({ error: 'Granite Chat Error', details: error.message });
  }
});


// In your existing server.js (CommonJS style)...

 app.post('/api/gemini-live/offer', async (req, res) => {
  try {
    const { sdp } = req.body || {};
    if (!sdp) return res.status(400).json({ error: 'missing_offer_sdp' });

    const modelName = MODEL || "gemini-2.0-flash";

    // Call Gemini Live with offer SDP
    const resp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:streamGenerateContent?alt=sdp&key=${GEMINI_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/sdp" },
        body: sdp,
      }
    );

    if (!resp.ok) {
      const txt = await resp.text();
      console.error("Gemini SDP exchange failed:", txt);
      return res.status(500).json({ error: "gemini_sdp_failed", details: txt });
    }

    const answerSdp = await resp.text();

    res.json({ ok: true, answer: answerSdp });
  } catch (err) {
    console.error("Offer error:", err);
    res.status(500).json({ error: "server_error", details: err.message });
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
