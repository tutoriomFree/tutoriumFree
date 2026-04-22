/**
 * ============================================================
 *  server.js  –  Production-grade API
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
 *    GET  /health                                              Health check
 *    GET  /classes                                             All classes with their subjects
 *    GET  /chapters?classId=&subjectId=                        Chapters for a class+subject
 *    GET  /posts?classId=&subjectId=&chapterId=                Posts (ordered oldest-first)
 *    GET  /posts/recent                                        Top 10 recent posts
 *    POST /visit                                               Record a site visit (public)
 *    GET  /visit-count                                         Today's visit count (public)
 *
 *  ENDPOINTS (admin – X-Admin-Secret header required):
 *    GET    /queue-stats                  Live queue metrics
 *    POST   /admin/cache/rebuild          Force full cache refresh
 *    GET    /visit-stats                  Visits: today / week / month / total
 *
 *    POST   /admin/classes                Create a new class
 *    POST   /admin/subjects               Create a new subject (validates classId exists)
 *    POST   /admin/chapters               Create a new chapter (validates classId + subjectId exist)
 *    POST   /admin/posts                  Create a new post   (validates classId + subjectId + chapterId exist)
 *    PUT    /admin/posts                  Edit an existing post by postId in body
 *    DELETE /admin/posts                  Delete a post by postId in body
 */
'use strict';

const express   = require('express');
const cors      = require('cors');
const admin     = require('firebase-admin');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');
const pino      = require('pino');
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
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
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

/**
 * Tighter limiter for admin write endpoints.
 * Prevents accidental bulk-write abuse or brute-force on the secret.
 */
const adminWriteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) =>
    res.status(429).json({ error: 'Too many admin requests. Please slow down.' }),
});

app.use(globalLimiter);

// ─────────────────────────────────────────────
// Input validation helpers
// ─────────────────────────────────────────────
const ID_REGEX   = /^[a-zA-Z0-9_\-@.+]{1,256}$/;
// Allows letters, digits, spaces, and common punctuation – used for human-readable names
const NAME_REGEX = /^[a-zA-Z0-9 _\-.,()&']{1,200}$/;
const TITLE_REGEX = /^[\s\S]{1,500}$/;
// URL validation (basic – allows http/https)
const URL_REGEX  = /^https?:\/\/.{1,2000}$/;

function validateId(value, name) {
  if (!value || typeof value !== 'string' || !ID_REGEX.test(value)) {
    throw new Error(`BAD_REQUEST: Invalid ${name} format`);
  }
}

function validateName(value, name) {
  if (!value || typeof value !== 'string' || !NAME_REGEX.test(value.trim())) {
    throw new Error(`BAD_REQUEST: Invalid or missing ${name}`);
  }
}

function validateUrl(value, name) {
  if (!value || typeof value !== 'string' || !URL_REGEX.test(value.trim())) {
    throw new Error(`BAD_REQUEST: Invalid or missing ${name} (must be a valid http/https URL)`);
  }
}

function requireQueryParams(query, ...names) {
  for (const name of names) {
    if (!query[name]) throw new Error(`BAD_REQUEST: ${name} is required`);
    validateId(query[name], name);
  }
}

/**
 * Require body fields to be non-empty strings and return their trimmed values.
 * Throws BAD_REQUEST if any field is missing or blank.
 */
function requireBodyFields(body, ...names) {
  const result = {};
  for (const name of names) {
    const val = body[name];
    if (!val || typeof val !== 'string' || !val.trim()) {
      throw new Error(`BAD_REQUEST: ${name} is required`);
    }
    result[name] = val.trim();
  }
  return result;
}

// ─────────────────────────────────────────────
// ID generators
// ─────────────────────────────────────────────

/** Returns a random 4-digit number string, e.g. "0472" */
function rand4() {
  return String(Math.floor(1000 + Math.random() * 9000));
}

/** Returns a random 10-digit number string, e.g. "3847201956" */
function rand10() {
  // Use crypto for better randomness
  const buf = crypto.randomBytes(5); // 5 bytes = 40 bits → up to 1.1e12
  const num = (buf.readUIntBE(0, 5) % 9_000_000_000) + 1_000_000_000;
  return String(num);
}

/**
 * Slugify a human-readable name for use in IDs:
 * "Class 10 Science" → "Class10Science"
 * Strips spaces and special chars, keeps alphanumeric only, max 40 chars.
 */
function slugify(name) {
  return name
    .replace(/[^a-zA-Z0-9]/g, '')
    .slice(0, 40);
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
 * Called on startup and on /admin/cache/rebuild.
 * Also called automatically after every successful admin write
 * so reads stay consistent without a manual rebuild.
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
  read:  new Queue(100, 10000, 15000), // public read endpoints
  write: new Queue(20,  500,   20000), // admin write endpoints (lower concurrency)
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

  if (msg.startsWith('CONFLICT:'))
    return res.status(409).json({ error: msg.replace('CONFLICT:', '').trim() });

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
// Reference validation helpers
// These hit Firestore to confirm parent documents exist
// before allowing child documents to be created.
// ─────────────────────────────────────────────

/** Throws NOT_FOUND if the classId document doesn't exist in the cache. */
function requireClassInCache(classId) {
  const exists = cache.classes.some(c => c.classId === classId);
  if (!exists) throw new Error(`NOT_FOUND: classId "${classId}" does not exist`);
}

/** Throws NOT_FOUND if the subjectId is not in the cache under the given classId. */
function requireSubjectInCache(classId, subjectId) {
  const subjects = cache.subjects.get(classId) ?? [];
  const exists   = subjects.some(s => s.subjectId === subjectId);
  if (!exists)
    throw new Error(`NOT_FOUND: subjectId "${subjectId}" does not exist under classId "${classId}"`);
}

/** Throws NOT_FOUND if the chapterId is not in the cache under the given classId + subjectId. */
function requireChapterInCache(classId, subjectId, chapterId) {
  const key      = `${classId}|${subjectId}`;
  const chapters = cache.chapters.get(key) ?? [];
  const exists   = chapters.some(c => c.chapterId === chapterId);
  if (!exists)
    throw new Error(
      `NOT_FOUND: chapterId "${chapterId}" does not exist under classId "${classId}" / subjectId "${subjectId}"`
    );
}

// ─────────────────────────────────────────────
// ════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════
// ─────────────────────────────────────────────

// ── Health check ──────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    status:       'ok',
    firebase:     firebaseInitialized,
    cacheBuiltAt: cache.builtAt ? cache.builtAt.toISOString() : null,
    uptime:       process.uptime(),
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
      success:    true,
      message:    'Cache rebuilt successfully',
      builtAt:    cache.builtAt?.toISOString(),
      classCount: cache.classes.length,
    });
  } catch (err) {
    logger.error({ err }, 'Cache rebuild failed');
    res.status(500).json({ error: 'Cache rebuild failed' });
  }
});

// ─────────────────────────────────────────────
// ENDPOINT — GET /classes
//   Returns all classes with their nested subjects array.
//   Source: in-memory cache (no DB hit at runtime).
// ─────────────────────────────────────────────
app.get('/classes', async (req, res) => {
  try {
    const result = await QUEUES.read.add(async () => {
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
// ENDPOINT — GET /chapters?classId=&subjectId=
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
// ENDPOINT — GET /posts?classId=&subjectId=&chapterId=
//   Returns posts for the given filter combination,
//   ordered oldest → newest (ascending createdAt).
//   Also used by admin to preview posts before editing/deleting.
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
        .orderBy('createdAt', 'asc')
        .get();

      return snap.docs.map((doc, idx) => {
        const d = doc.data();
        return {
          postId:       String(d.postId       ?? doc.id),
          postTitle:    String(d.postTitle    ?? ''),
          postSubtitle: String(d.postSubtitle ?? ''),
          tutorName:    String(d.tutorName    ?? ''),
          videoUrl:     String(d.videoUrl     ?? ''),
          thumbnailUrl: String(d.thumbnailUrl ?? ''),
          classId:      String(d.classId      ?? ''),
          subjectId:    String(d.subjectId    ?? ''),
          chapterId:    String(d.chapterId    ?? ''),
          createdAt:    d.createdAt?.toDate?.()?.toISOString() ?? null,
          updatedAt:    d.updatedAt?.toDate?.()?.toISOString() ?? null,
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
// ENDPOINT — GET /posts/recent
//   Returns the 10 most recently created posts across all classes
//   (sorted newest-first). No parameters required.
// ─────────────────────────────────────────────
app.get('/posts/recent', async (req, res) => {
  try {
    const result = await QUEUES.read.add(async () => {
      requireDb();

      const snap = await db.collection('posts')
        .orderBy('createdAt', 'desc')
        .limit(10)
        .get();

      return snap.docs.map(doc => {
        const d = doc.data();
        return {
          postId:       String(d.postId       ?? doc.id),
          postTitle:    String(d.postTitle    ?? ''),
          postSubtitle: String(d.postSubtitle ?? ''),
          tutorName:    String(d.tutorName    ?? ''),
          videoUrl:     String(d.videoUrl     ?? ''),
          thumbnailUrl: String(d.thumbnailUrl ?? ''),
          classId:      String(d.classId      ?? ''),
          subjectId:    String(d.subjectId    ?? ''),
          chapterId:    String(d.chapterId    ?? ''),
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
// ENDPOINT — POST /visit
//   Records a single site visit for today.
//   No auth required (public endpoint).
// ─────────────────────────────────────────────
app.post('/visit', async (req, res) => {
  try {
    await QUEUES.read.add(async () => {
      requireDb();
      const today = new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
      const ref   = db.collection('site_visits').doc(today);
      await ref.set(
        { count: admin.firestore.FieldValue.increment(1), date: today },
        { merge: true }
      );
    });
    res.status(200).json({ success: true });
  } catch (err) {
    handleError(err, res);
  }
});

// ─────────────────────────────────────────────
// ENDPOINT — GET /visit-stats  (admin)
//   Returns visit counts: today, this week, this month, total.
// ─────────────────────────────────────────────
app.get('/visit-stats', requireAdminSecret, async (req, res) => {
  try {
    const result = await QUEUES.read.add(async () => {
      requireDb();

      const now           = new Date();
      const todayStr      = now.toISOString().slice(0, 10);
      const dayOfWeek     = (now.getDay() + 6) % 7;
      const weekStart     = new Date(now);
      weekStart.setDate(now.getDate() - dayOfWeek);
      const weekStartStr  = weekStart.toISOString().slice(0, 10);
      const monthStartStr = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;

      const snap = await db.collection('site_visits')
        .where('date', '>=', monthStartStr)
        .orderBy('date', 'asc')
        .get();

      let daily = 0, weekly = 0, monthly = 0;
      snap.forEach(doc => {
        const { date, count } = doc.data();
        const n = Number(count) || 0;
        monthly += n;
        if (date >= weekStartStr) weekly += n;
        if (date === todayStr)    daily   = n;
      });

      const totalSnap = await db.collection('site_visits').get();
      let total = 0;
      totalSnap.forEach(doc => { total += Number(doc.data().count) || 0; });

      return { daily, weekly, monthly, total, asOf: now.toISOString() };
    });
    res.json(result);
  } catch (err) {
    handleError(err, res);
  }
});

// ── GET /visit-count  (public – today's count only) ──
app.get('/visit-count', async (req, res) => {
  try {
    const result = await QUEUES.read.add(async () => {
      requireDb();
      const today = new Date().toISOString().slice(0, 10);
      const doc   = await db.collection('site_visits').doc(today).get();
      return { count: doc.exists ? (Number(doc.data().count) || 0) : 0 };
    });
    res.json(result);
  } catch (err) {
    handleError(err, res);
  }
});

// ═══════════════════════════════════════════════════════
//  ADMIN WRITE ENDPOINTS
// ═══════════════════════════════════════════════════════

// ─────────────────────────────────────────────
// ADMIN ENDPOINT 1 — POST /admin/classes
//
//  Creates a new class document in Firestore.
//
//  Request body:
//    { "className": "Class 10" }
//
//  ID format: class_{slugifiedName}{rand4}
//    e.g.  class_Class104721
//
//  Steps:
//    1. Validate className (required, name format)
//    2. Generate classId
//    3. Write to Firestore
//    4. Patch the in-memory cache immediately (no full rebuild needed)
//
//  Response 201:
//    { "success": true, "classId": "class_Class104721", "className": "Class 10" }
//
//  Errors:
//    400 – missing / invalid className
//    409 – className already exists (case-insensitive check)
//    503 – queue full
// ─────────────────────────────────────────────
app.post(
  '/admin/classes',
  requireAdminSecret,
  adminWriteLimiter,
  async (req, res) => {
    try {
      const result = await QUEUES.write.add(async () => {
        requireDb();

        const { className } = requireBodyFields(req.body, 'className');
        validateName(className, 'className');

        // Duplicate check (case-insensitive) against cache
        const duplicate = cache.classes.some(
          c => c.className.toLowerCase() === className.toLowerCase()
        );
        if (duplicate)
          throw new Error(`CONFLICT: A class named "${className}" already exists`);

        const classId = `class_${slugify(className)}${rand4()}`;

        const docData = {
          classId,
          className,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        await db.collection('classes').doc(classId).set(docData);
        logger.info({ classId, className }, '✅ Class created');

        // Patch cache – no full rebuild required
        cache.classes.push({ classId, className });

        return { success: true, classId, className };
      });

      res.status(201).json(result);
    } catch (err) {
      handleError(err, res);
    }
  }
);

// ─────────────────────────────────────────────
// ADMIN ENDPOINT 2 — POST /admin/subjects
//
//  Creates a new subject document under an existing class.
//
//  Request body:
//    { "classId": "class_Class104721", "subjectName": "Mathematics" }
//
//  ID format: subject_{slugifiedName}{rand4}
//    e.g.  subject_Mathematics3812
//
//  Steps:
//    1. Validate classId (must exist in cache)
//    2. Validate subjectName
//    3. Duplicate check: same subjectName under same classId
//    4. Write to Firestore
//    5. Patch in-memory cache
//
//  Response 201:
//    { "success": true, "subjectId": "...", "subjectName": "...", "classId": "..." }
//
//  Errors:
//    400 – missing fields or bad format
//    404 – classId not found
//    409 – subjectName already exists under this class
// ─────────────────────────────────────────────
app.post(
  '/admin/subjects',
  requireAdminSecret,
  adminWriteLimiter,
  async (req, res) => {
    try {
      const result = await QUEUES.write.add(async () => {
        requireDb();

        const { classId, subjectName } = requireBodyFields(req.body, 'classId', 'subjectName');
        validateId(classId, 'classId');
        validateName(subjectName, 'subjectName');

        // Validate parent reference
        requireClassInCache(classId);

        // Duplicate check under this class
        const existingSubjects = cache.subjects.get(classId) ?? [];
        const duplicate = existingSubjects.some(
          s => s.subjectName.toLowerCase() === subjectName.toLowerCase()
        );
        if (duplicate)
          throw new Error(
            `CONFLICT: A subject named "${subjectName}" already exists under this class`
          );

        const subjectId = `subject_${slugify(subjectName)}${rand4()}`;

        const docData = {
          subjectId,
          subjectName,
          classId,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        await db.collection('subjects').doc(subjectId).set(docData);
        logger.info({ subjectId, subjectName, classId }, '✅ Subject created');

        // Patch cache
        if (!cache.subjects.has(classId)) cache.subjects.set(classId, []);
        cache.subjects.get(classId).push({ subjectId, subjectName });

        return { success: true, subjectId, subjectName, classId };
      });

      res.status(201).json(result);
    } catch (err) {
      handleError(err, res);
    }
  }
);

// ─────────────────────────────────────────────
// ADMIN ENDPOINT 3 — POST /admin/chapters
//
//  Creates a new chapter document under an existing class + subject.
//
//  Request body:
//    { "classId": "...", "subjectId": "...", "chapterName": "Algebra" }
//
//  ID format: chapter_{slugifiedName}{rand4}
//    e.g.  chapter_Algebra5591
//
//  Steps:
//    1. Validate classId  (must exist in cache)
//    2. Validate subjectId (must exist under classId in cache)
//    3. Validate chapterName
//    4. Duplicate check: same chapterName under same classId + subjectId
//    5. Write to Firestore
//    6. Patch in-memory cache
//
//  Response 201:
//    { "success": true, "chapterId": "...", "chapterName": "...", "classId": "...", "subjectId": "..." }
//
//  Errors:
//    400 – missing fields or bad format
//    404 – classId or subjectId not found
//    409 – chapterName already exists under this class + subject
// ─────────────────────────────────────────────
app.post(
  '/admin/chapters',
  requireAdminSecret,
  adminWriteLimiter,
  async (req, res) => {
    try {
      const result = await QUEUES.write.add(async () => {
        requireDb();

        const { classId, subjectId, chapterName } = requireBodyFields(
          req.body,
          'classId',
          'subjectId',
          'chapterName'
        );
        validateId(classId,   'classId');
        validateId(subjectId, 'subjectId');
        validateName(chapterName, 'chapterName');

        // Validate parent references (both must exist)
        requireClassInCache(classId);
        requireSubjectInCache(classId, subjectId);

        // Duplicate check under this class + subject
        const cacheKey         = `${classId}|${subjectId}`;
        const existingChapters = cache.chapters.get(cacheKey) ?? [];
        const duplicate        = existingChapters.some(
          c => c.chapterName.toLowerCase() === chapterName.toLowerCase()
        );
        if (duplicate)
          throw new Error(
            `CONFLICT: A chapter named "${chapterName}" already exists under this subject`
          );

        const chapterId = `chapter_${slugify(chapterName)}${rand4()}`;

        const docData = {
          chapterId,
          chapterName,
          classId,
          subjectId,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        await db.collection('chapters').doc(chapterId).set(docData);
        logger.info({ chapterId, chapterName, classId, subjectId }, '✅ Chapter created');

        // Patch cache
        if (!cache.chapters.has(cacheKey)) cache.chapters.set(cacheKey, []);
        cache.chapters.get(cacheKey).push({ chapterId, chapterName });

        return { success: true, chapterId, chapterName, classId, subjectId };
      });

      res.status(201).json(result);
    } catch (err) {
      handleError(err, res);
    }
  }
);

// ─────────────────────────────────────────────
// ADMIN ENDPOINT 4 — POST /admin/posts
//
//  Creates a new post document.
//
//  Request body:
//    {
//      "classId":      "...",
//      "subjectId":    "...",
//      "chapterId":    "...",
//      "postTitle":    "Introduction to Algebra",
//      "postSubtitle": "Learn the basics",
//      "tutorName":    "Mr. Smith",
//      "videoUrl":     "https://...",
//      "thumbnailUrl": "https://..."
//    }
//
//  ID format: post_{rand10}
//    e.g. post_3847201956
//
//  Steps:
//    1. Validate all body fields
//    2. Validate classId, subjectId, chapterId references
//    3. Validate videoUrl and thumbnailUrl are valid URLs
//    4. Write to Firestore with server-side createdAt timestamp
//
//  Response 201:
//    { "success": true, "postId": "post_3847201956", ...allFields }
//
//  Errors:
//    400 – missing/invalid fields or invalid URLs
//    404 – classId / subjectId / chapterId not found
// ─────────────────────────────────────────────
app.post(
  '/admin/posts',
  requireAdminSecret,
  adminWriteLimiter,
  async (req, res) => {
    try {
      const result = await QUEUES.write.add(async () => {
        requireDb();

        const {
          classId,
          subjectId,
          chapterId,
          postTitle,
          postSubtitle,
          tutorName,
          videoUrl,
          thumbnailUrl
        } = requireBodyFields(
          req.body,
          'classId',
          'subjectId',
          'chapterId',
          'postTitle',
          'postSubtitle',
          'tutorName',
          'videoUrl'
        );
        const thumbnailUrl = (req.body.thumbnailUrl || '').trim(); // optional, default empty string

        // Validate IDs
        validateId(classId,   'classId');
        validateId(subjectId, 'subjectId');
        validateId(chapterId, 'chapterId');

        // Validate name fields
        if (!TITLE_REGEX.test(postTitle))    throw new Error('BAD_REQUEST: Invalid or missing postTitle');
        if (!TITLE_REGEX.test(postSubtitle)) throw new Error('BAD_REQUEST: Invalid or missing postSubtitle');
        validateName(tutorName,    'tutorName');

        // Validate URLs
        validateUrl(videoUrl,     'videoUrl');
        

        // Validate all parent references exist
        requireClassInCache(classId);
        requireSubjectInCache(classId, subjectId);
        requireChapterInCache(classId, subjectId, chapterId);

        const postId = `post_${rand10()}`;

        const docData = {
          postId,
          classId,
          subjectId,
          chapterId,
          postTitle,
          postSubtitle,
          tutorName,
          videoUrl,
          thumbnailUrl,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        await db.collection('posts').doc(postId).set(docData);
        logger.info({ postId, postTitle, classId, subjectId, chapterId }, '✅ Post created');

        return {
          success: true,
          postId,
          classId,
          subjectId,
          chapterId,
          postTitle,
          postSubtitle,
          tutorName,
          videoUrl,
          thumbnailUrl,
        };
      });

      res.status(201).json(result);
    } catch (err) {
      handleError(err, res);
    }
  }
);

// ─────────────────────────────────────────────
// ADMIN ENDPOINT 5 — PUT /admin/posts
//
//  Edits an existing post. Only the fields provided in the
//  request body are updated (partial update / patch semantics).
//  postId is required and identifies the document to update.
//
//  Request body (postId required; all other fields optional):
//    {
//      "postId":       "post_3847201956",   ← required
//      "postTitle":    "Updated Title",     ← optional
//      "postSubtitle": "Updated subtitle",  ← optional
//      "tutorName":    "Mrs. Johnson",      ← optional
//      "videoUrl":     "https://...",       ← optional
//      "thumbnailUrl": "https://...",       ← optional
//      "classId":      "...",               ← optional (re-assign chapter)
//      "subjectId":    "...",               ← optional (re-assign chapter)
//      "chapterId":    "...",               ← optional (re-assign chapter)
//    }
//
//  Steps:
//    1. Validate postId
//    2. Confirm post document exists in Firestore
//    3. Validate and collect only the provided editable fields
//    4. If classId/subjectId/chapterId are being changed, re-validate all three together
//    5. Merge-update the document + set updatedAt timestamp
//
//  Response 200:
//    { "success": true, "postId": "...", "updated": { ...changedFields } }
//
//  Errors:
//    400 – missing postId or invalid field values
//    404 – postId document not found
// ─────────────────────────────────────────────
app.put(
  '/admin/posts',
  requireAdminSecret,
  adminWriteLimiter,
  async (req, res) => {
    try {
      const result = await QUEUES.write.add(async () => {
        requireDb();

        const { postId } = requireBodyFields(req.body, 'postId');
        validateId(postId, 'postId');

        // Confirm post exists
        const docRef  = db.collection('posts').doc(postId);
        const docSnap = await docRef.get();
        if (!docSnap.exists)
          throw new Error(`NOT_FOUND: Post with postId "${postId}" does not exist`);

        const existingData = docSnap.data();
        const updates      = {};

        // ── Optional text fields ──────────────────────────────
        const textFields = ['postTitle', 'postSubtitle', 'tutorName'];
        for (const field of textFields) {
          const val = req.body[field];
          if (val !== undefined) {
            if (!val || typeof val !== 'string' || !val.trim())
              throw new Error(`BAD_REQUEST: ${field} cannot be empty`);
            validateName(val.trim(), field);
            updates[field] = val.trim();
          }
        }

        // ── Optional URL fields ───────────────────────────────
        const urlFields = ['videoUrl', 'thumbnailUrl'];
        for (const field of urlFields) {
          const val = req.body[field];
          if (val !== undefined) {
            validateUrl(val.trim(), field);
            updates[field] = val.trim();
          }
        }

        // ── Optional reference re-assignment ──────────────────
        // If ANY of classId / subjectId / chapterId is provided,
        // all three must be supplied together and valid.
        const hasClassId   = req.body.classId   !== undefined;
        const hasSubjectId = req.body.subjectId !== undefined;
        const hasChapterId = req.body.chapterId !== undefined;

        if (hasClassId || hasSubjectId || hasChapterId) {
          if (!hasClassId || !hasSubjectId || !hasChapterId)
            throw new Error(
              'BAD_REQUEST: When re-assigning a chapter, classId, subjectId, and chapterId must all be provided together'
            );

          const newClassId   = String(req.body.classId).trim();
          const newSubjectId = String(req.body.subjectId).trim();
          const newChapterId = String(req.body.chapterId).trim();

          validateId(newClassId,   'classId');
          validateId(newSubjectId, 'subjectId');
          validateId(newChapterId, 'chapterId');

          requireClassInCache(newClassId);
          requireSubjectInCache(newClassId, newSubjectId);
          requireChapterInCache(newClassId, newSubjectId, newChapterId);

          updates.classId   = newClassId;
          updates.subjectId = newSubjectId;
          updates.chapterId = newChapterId;
        }

        if (Object.keys(updates).length === 0)
          throw new Error('BAD_REQUEST: No updatable fields provided');

        updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();

        await docRef.update(updates);
        logger.info({ postId, updates: Object.keys(updates) }, '✅ Post updated');

        // Return merged view of the post for the frontend
        const { updatedAt, ...updatedFields } = updates; // exclude server timestamp from response
        return {
          success:  true,
          postId,
          updated:  updatedFields,
          // Return full current state (merge existing + updates for convenience)
          current: {
            ...existingData,
            ...updatedFields,
            postId,
            createdAt: existingData.createdAt?.toDate?.()?.toISOString() ?? null,
          },
        };
      });

      res.status(200).json(result);
    } catch (err) {
      handleError(err, res);
    }
  }
);

// ─────────────────────────────────────────────
// ADMIN ENDPOINT 6 — DELETE /admin/posts
//
//  Permanently deletes a post document by postId.
//
//  Request body:
//    { "postId": "post_3847201956" }
//
//  Steps:
//    1. Validate postId
//    2. Confirm post document exists (prevents silent no-ops)
//    3. Delete the document from Firestore
//
//  Response 200:
//    { "success": true, "message": "Post post_3847201956 deleted successfully.", "postId": "..." }
//
//  Errors:
//    400 – missing or invalid postId
//    404 – post not found
// ─────────────────────────────────────────────
app.delete(
  '/admin/posts',
  requireAdminSecret,
  adminWriteLimiter,
  async (req, res) => {
    try {
      const result = await QUEUES.write.add(async () => {
        requireDb();

        const { postId } = requireBodyFields(req.body, 'postId');
        validateId(postId, 'postId');

        // Confirm post exists before deleting
        const docRef  = db.collection('posts').doc(postId);
        const docSnap = await docRef.get();
        if (!docSnap.exists)
          throw new Error(`NOT_FOUND: Post with postId "${postId}" does not exist`);

        await docRef.delete();
        logger.info({ postId }, '🗑️  Post deleted');

        return {
          success: true,
          message: `Post ${postId} deleted successfully.`,
          postId,
        };
      });

      res.status(200).json(result);
    } catch (err) {
      handleError(err, res);
    }
  }
);

// ─────────────────────────────────────────────
// 404 fallback
// ─────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ─────────────────────────────────────────────
// Start server + warm up cache
// ─────────────────────────────────────────────
app.listen(PORT, async () => {
  logger.info(`🚀 Server running on port ${PORT} (${process.env.NODE_ENV ?? 'development'})`);
  try {
    await buildCache();
  } catch (err) {
    logger.error({ err }, 'Initial cache build failed – server is still running');
  }
});
