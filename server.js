// server.js

const express = require('express');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const path = require('path');
const multer = require('multer');
const pdfParse = require('pdf-parse');

const app = express();
const PORT = process.env.PORT || 5000;

// Prefer env var; fallback to hardcoded key (discouraged in production)
const GEMINI_API_KEY =
  process.env.GEMINI_API_KEY || 'AIzaSyBxfK1fAJjzJImC6VheREpSNxl-JbVeb6g';

// -------- Multer config for PDF uploads (multiple) --------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB per file
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files are allowed'), false);
  },
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

// -------- Helpers --------
const MODEL = 'gemini-2.0-flash'; // ✅ Updated model

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
    // Provide best-effort detail back to client
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

// Build Gemini "contents" array from chat messages and optional PDF context
function buildContents({ messages, pdfContexts }) {
  const contents = [];

  // existing chat history
  for (const m of messages || []) {
    contents.push({
      role: toGeminiRole(m.role),
      parts: [{ text: m.content }],
    });
  }

  // If we have PDF contexts, append them as additional user parts
  if (pdfContexts && pdfContexts.length > 0) {
    for (const ctx of pdfContexts) {
      // Each PDF context may be large; chunk it
      const header = `# SOURCE: ${ctx.filename}\n(Extracted text below)`;
      contents.push({ role: 'user', parts: [{ text: header }] });

      const chunks = chunkText(ctx.text);
      // Cap number of chunks per file to avoid overlong payload (tune as needed)
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

// -------- Single Chat Endpoint --------
// Works as:
// - JSON body: { messages: [...] }  -> normal chat
// - multipart/form-data: fields: messages (JSON string), files: pdfs[] -> chat grounded in PDFs
app.post('/api/chat', upload.array('files', 10), async (req, res) => {
  try {
    const isMultipart = req.headers['content-type']?.includes('multipart/form-data');

    // 1) Get messages (from JSON body or multipart field)
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

    // 2) If PDFs uploaded, parse them
    let pdfContexts = [];
    if (isMultipart && req.files && req.files.length > 0) {
      // Extract text from all PDFs
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

    // 3) Create system instruction
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

    // 4) Build Gemini request contents
    const contents = buildContents({ messages, pdfContexts });

    // 5) Call Gemini
    const data = await callGemini(MODEL, { systemText, contents });

    // 6) Extract model text
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

// -------- Health Check --------
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Server is running',
    environment: process.env.NODE_ENV || 'development',
  });
});

// -------- Start Server --------
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 CORS allowed from: ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(`🔍 Health check: http://localhost:${PORT}/api/health`);
  console.log(`💬 Chat endpoint:   http://localhost:${PORT}/api/chat`);
});

module.exports = app;
