/**
 * ============================================================
 *  server.js  –  Production-grade public API (no auth on reads)
 * ============================================================
 *
 *  DEPENDENCIES (add to package.json):
 *    express, cors, express-rate-limit, pino, pino-pretty,
 *    firebase-admin, dotenv, crypto (built-in)
 *
 *  ENV VARS:
 *    PORT                     – default 3000
 *    NODE_ENV                 – "production" | "development"
 *    ALLOWED_ORIGINS          – comma-separated list of allowed CORS origins
 *    FIREBASE_SERVICE_ACCOUNT – JSON string of Firebase service-account key
 *    ADMIN_SECRET             – secret header value for admin endpoints
 *
 *  ENDPOINTS (public – no authentication required):
 *    GET  /health                        Health check
 *    GET  /classes                       All classes with their subjects
 *    GET  /chapters?classId=&subjectId=  Chapters for a class+subject
 *    GET  /posts?classId=&subjectId=&chapterId=   Posts (ordered oldest-first)
 *    GET  /posts/recent?classId=         Top 10 recent posts for a class
 *
 *  ENDPOINTS (admin – X-Admin-Secret header required):
 *    GET    /queue-stats                 Live queue metrics
 *    POST   /admin/cache/rebuild         Force full cache refresh
 */

'use strict';

const express    = require('express');
const cors       = require('cors');
const admin      = require('firebase-admin');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const pino       = require('pino');
require('dotenv').config();

// ─────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────
const app          = express();
const PORT         = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// ─────────────────────────────────────────────
// Logger
// ─────────────────────────────────────────────
const logger = pino({
  level: isProduction ? 'info' : 'debug',
  transport: !isProduction
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
});

// ─────────────────────────────────────────────
// Trust proxy (required for accurate rate-limit IP detection)
// ─────────────────────────────────────────────
app.set('trust proxy', 1);

// ─────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser clients (curl, mobile SDKs, server-to-server)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: Origin "${origin}" is not allowed`));
  },
  allowedHeaders: ['Content-Type', 'X-Admin-Secret'],
  methods: ['GET', 'POST'],
}));

// ─────────────────────────────────────────────
// Body parsers
// ─────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: false }));

// ─────────────────────────────────────────────
// Rate limiters
// ─────────────────────────────────────────────

/** Applied globally to every route */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) =>
    res.status(429).json({ error: 'Too many requests. Please slow down.' }),
});

app.use(globalLimiter);

// ─────────────────────────────────────────────
// Input validation helpers
// ─────────────────────────────────────────────
const ID_REGEX = /^[a-zA-Z0-9_\-@.+]{1,256}$/;

function validateId(value, name) {
  if (!value || typeof value !== 'string' || !ID_REGEX.test(value)) {
    throw new Error(`BAD_REQUEST: Invalid ${name} format`);
  }
}

function requireQueryParams(query, ...names) {
  for (const name of names) {
    if (!query[name]) throw new Error(`BAD_REQUEST: ${name} is required`);
    validateId(query[name], name);
  }
}

// ─────────────────────────────────────────────
// Firebase initialisation
// ─────────────────────────────────────────────
let db                  = null;
let firebaseInitialized = false;

try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    db                  = admin.firestore();
    firebaseInitialized = true;
    logger.info('✅ Firebase Admin initialized');
  } else {
    logger.warn('⚠️  FIREBASE_SERVICE_ACCOUNT not set – Firestore unavailable');
  }
} catch (err) {
  logger.error({ err }, '❌ Failed to initialize Firebase Admin');
}

// ─────────────────────────────────────────────
// In-Memory Cache
// ─────────────────────────────────────────────
/**
 * Shape stored in cache:
 *
 *   cache.classes   – Array<{ classId, className }>
 *   cache.subjects  – Map<classId, Array<{ subjectId, subjectName }>>
 *   cache.chapters  – Map<`${classId}|${subjectId}`, Array<{ chapterId, chapterName }>>
 *   cache.builtAt   – Date | null
 */
const cache = {
  classes:  [],
  subjects: new Map(),
  chapters: new Map(),
  builtAt:  null,
};

/**
 * Populate the in-memory cache with all classes, subjects, and chapters.
 * This is called on startup and can be manually triggered via /admin/cache/rebuild.
 */
async function buildCache() {
  if (!db) {
    logger.warn('buildCache: Firestore not available, skipping.');
    return;
  }

  logger.info('🔄 Building in-memory cache…');

  // 1. Fetch classes
  const classesSnap = await db.collection('classes').get();
  const newClasses  = [];
  classesSnap.forEach(doc => {
    const d = doc.data();
    if (d.classId && d.className) {
      newClasses.push({ classId: String(d.classId), className: String(d.className) });
    }
  });

  // 2. Fetch all subjects
  const subjectsSnap = await db.collection('subjects').get();
  const newSubjects  = new Map(); // classId → [{subjectId, subjectName}]

  subjectsSnap.forEach(doc => {
    const d = doc.data();
    if (!d.subjectId || !d.subjectName || !d.classId) return;
    const entry = { subjectId: String(d.subjectId), subjectName: String(d.subjectName) };
    if (!newSubjects.has(d.classId)) newSubjects.set(d.classId, []);
    newSubjects.get(d.classId).push(entry);
  });

  // 3. Fetch all chapters
  const chaptersSnap = await db.collection('chapters').get();
  const newChapters  = new Map(); // `${classId}|${subjectId}` → [{chapterId, chapterName}]

  chaptersSnap.forEach(doc => {
    const d = doc.data();
    if (!d.chapterId || !d.chapterName || !d.classId || !d.subjectId) return;
    const key   = `${d.classId}|${d.subjectId}`;
    const entry = { chapterId: String(d.chapterId), chapterName: String(d.chapterName) };
    if (!newChapters.has(key)) newChapters.set(key, []);
    newChapters.get(key).push(entry);
  });

  // 4. Atomically replace cache content
  cache.classes  = newClasses;
  cache.subjects = newSubjects;
  cache.chapters = newChapters;
  cache.builtAt  = new Date();

  logger.info(
    {
      classes:  newClasses.length,
      subjects: [...newSubjects.values()].reduce((s, a) => s + a.length, 0),
      chapters: [...newChapters.values()].reduce((s, a) => s + a.length, 0),
    },
    '✅ Cache built successfully'
  );
}

// ─────────────────────────────────────────────
// Queue  (concurrency + back-pressure)
// ─────────────────────────────────────────────
class Queue {
  constructor(concurrency = 50, maxSize = 5000, timeoutMs = 30000) {
    this.concurrency = concurrency;
    this.maxSize     = maxSize;
    this.timeoutMs   = timeoutMs;
    this._queue      = [];
    this._active     = 0;
  }

  getStats() {
    return {
      waiting:     this._queue.length,
      active:      this._active,
      concurrency: this.concurrency,
      maxSize:     this.maxSize,
    };
  }

  add(fn) {
    return new Promise((resolve, reject) => {
      if (this._queue.length + this._active >= this.maxSize) {
        return reject(new Error('QUEUE_FULL: Server is busy, please try again later.'));
      }
      const id = crypto.randomUUID();
      this._queue.push({ id, fn, resolve, reject });
      logger.debug(`Queue job ${id} enqueued. waiting=${this._queue.length} active=${this._active}`);
      this._drain();
    });
  }

  _drain() {
    while (this._active < this.concurrency && this._queue.length > 0) {
      const job = this._queue.shift();
      this._active++;
      const timeout = new Promise((_, rej) =>
        setTimeout(
          () => rej(new Error(`JOB_TIMEOUT: job ${job.id} exceeded ${this.timeoutMs}ms`)),
          this.timeoutMs
        )
      );
      Promise.race([job.fn(), timeout])
        .then(job.resolve)
        .catch(job.reject)
        .finally(() => {
          this._active--;
          this._drain();
        });
    }
  }
}

// ─────────────────────────────────────────────
// Queue Registry  (one queue per logical domain)
// ─────────────────────────────────────────────
const QUEUES = {
  read: new Queue(100, 10000, 15000), // public read endpoints
};

// ─────────────────────────────────────────────
// Error handler
// ─────────────────────────────────────────────
function handleError(err, res) {
  const msg = err.message || '';

  if (msg.startsWith('QUEUE_FULL:'))
    return res.status(503).json({ error: 'Server is busy. Please try again shortly.' });

  if (msg.startsWith('JOB_TIMEOUT:'))
    return res.status(504).json({ error: 'Request timed out. Please try again.' });

  if (msg.startsWith('BAD_REQUEST:'))
    return res.status(400).json({ error: msg.replace('BAD_REQUEST:', '').trim() });

  if (msg.startsWith('FORBIDDEN:'))
    return res.status(403).json({ error: msg.replace('FORBIDDEN:', '').trim() });

  if (msg.startsWith('NOT_FOUND:'))
    return res.status(404).json({ error: msg.replace('NOT_FOUND:', '').trim() });

  logger.error({ err }, 'Unhandled internal error');
  return res.status(500).json({ error: 'Internal server error' });
}

// ─────────────────────────────────────────────
// Admin middleware  (X-Admin-Secret header)
// ─────────────────────────────────────────────
function requireAdminSecret(req, res, next) {
  const secret = process.env.ADMIN_SECRET;
  if (!secret) {
    logger.error('ADMIN_SECRET env var not set');
    return res.status(500).json({ error: 'Server configuration error' });
  }
  if (req.headers['x-admin-secret'] !== secret)
    return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ─────────────────────────────────────────────
// Firestore guard
// ─────────────────────────────────────────────
function requireDb() {
  if (!db) throw new Error('BAD_REQUEST: Database not available');
}

// ─────────────────────────────────────────────
// ════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════
// ─────────────────────────────────────────────

// ── Health check ──────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    status:    'ok',
    firebase:  firebaseInitialized,
    cacheBuiltAt: cache.builtAt ? cache.builtAt.toISOString() : null,
    uptime:    process.uptime(),
  });
});

// ── Queue stats (admin only) ──────────────────
app.get('/queue-stats', requireAdminSecret, (_req, res) => {
  const stats = {};
  for (const [name, q] of Object.entries(QUEUES)) stats[name] = q.getStats();
  res.json(stats);
});

// ── Admin: force cache rebuild ────────────────
app.post('/admin/cache/rebuild', requireAdminSecret, async (_req, res) => {
  try {
    await buildCache();
    res.json({
      success:     true,
      message:     'Cache rebuilt successfully',
      builtAt:     cache.builtAt?.toISOString(),
      classCount:  cache.classes.length,
    });
  } catch (err) {
    logger.error({ err }, 'Cache rebuild failed');
    res.status(500).json({ error: 'Cache rebuild failed' });
  }
});

// ─────────────────────────────────────────────
// ENDPOINT 1 — GET /classes
//   Returns all classes with their nested subjects array.
//   Source: in-memory cache (no DB hit at runtime).
// ─────────────────────────────────────────────
app.get('/classes', async (req, res) => {
  try {
    const result = await QUEUES.read.add(async () => {
      // Build response: attach subjects array to each class
      return cache.classes.map(cls => ({
        classId:   cls.classId,
        className: cls.className,
        subjects:  cache.subjects.get(cls.classId) ?? [],
      }));
    });
    res.json(result);
  } catch (err) {
    handleError(err, res);
  }
});

// ─────────────────────────────────────────────
// ENDPOINT 2 — GET /chapters?classId=&subjectId=
//   Returns chapters matching the given classId + subjectId.
//   Source: in-memory cache.
// ─────────────────────────────────────────────
app.get('/chapters', async (req, res) => {
  try {
    const result = await QUEUES.read.add(async () => {
      requireQueryParams(req.query, 'classId', 'subjectId');
      const { classId, subjectId } = req.query;

      const key      = `${classId}|${subjectId}`;
      const chapters = cache.chapters.get(key) ?? [];
      return chapters;
    });
    res.json(result);
  } catch (err) {
    handleError(err, res);
  }
});

// ─────────────────────────────────────────────
// ENDPOINT 3 — GET /posts?classId=&subjectId=&chapterId=
//   Returns posts for the given filter combination,
//   ordered oldest → newest (ascending createdAt).
// ─────────────────────────────────────────────
app.get('/posts', async (req, res) => {
  try {
    const result = await QUEUES.read.add(async () => {
      requireDb();
      requireQueryParams(req.query, 'classId', 'subjectId', 'chapterId');
      const { classId, subjectId, chapterId } = req.query;

      const snap = await db.collection('posts')
        .where('classId',   '==', classId)
        .where('subjectId', '==', subjectId)
        .where('chapterId', '==', chapterId)
        .orderBy('createdAt', 'asc')  // oldest first
        .get();

      return snap.docs.map((doc, idx) => {
        const d = doc.data();
        return {
          postId:       String(d.postId       ?? doc.id),
          postTitle:    String(d.postTitle    ?? ''),
          postSubtitle: String(d.postSubtitle ?? ''),
          tutorId:      String(d.tutorId      ?? ''),
          tutorName:    String(d.tutorName    ?? ''),
          videoUrl:     String(d.videoUrl     ?? ''),
          thumbnailUrl: String(d.thumbnailUrl ?? ''),
          createdAt:    d.createdAt?.toDate?.()?.toISOString() ?? null,
          order:        idx + 1,
        };
      });
    });
    res.json(result);
  } catch (err) {
    handleError(err, res);
  }
});

// ─────────────────────────────────────────────
// ENDPOINT 4 — GET /posts/recent?classId=
//   Returns the 10 most recently created posts for a class
//   (sorted newest-first).
// ─────────────────────────────────────────────
app.get('/posts/recent', async (req, res) => {
  try {
    const result = await QUEUES.read.add(async () => {
      requireDb();
      requireQueryParams(req.query, 'classId');
      const { classId } = req.query;

      const snap = await db.collection('posts')
        .where('classId', '==', classId)
        .orderBy('createdAt', 'desc')
        .limit(10)
        .get();

      return snap.docs.map(doc => {
        const d = doc.data();
        return {
          postId:       String(d.postId       ?? doc.id),
          postTitle:    String(d.postTitle    ?? ''),
          postSubtitle: String(d.postSubtitle ?? ''),
          tutorId:      String(d.tutorId      ?? ''),
          tutorName:    String(d.tutorName    ?? ''),
          videoUrl:     String(d.videoUrl     ?? ''),
          thumbnailUrl: String(d.thumbnailUrl ?? ''),
          createdAt:    d.createdAt?.toDate?.()?.toISOString() ?? null,
        };
      });
    });
    res.json(result);
  } catch (err) {
    handleError(err, res);
  }
});

// ─────────────────────────────────────────────
// 404 fallback
// ─────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ─────────────────────────────────────────────
// Start server + warm up cache
// ─────────────────────────────────────────────
app.listen(PORT, async () => {
  logger.info(`🚀 Server running on port ${PORT} (${process.env.NODE_ENV ?? 'development'})`);

  // Build cache immediately on startup
  try {
    await buildCache();
  } catch (err) {
    logger.error({ err }, 'Initial cache build failed – server is still running');
  }
});
