const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3847;
const DATA_FILE = path.join(__dirname, 'data', 'rsvps.json');
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const MAX_RSVPS = 200;
const GUESTS_FILE = path.join(__dirname, 'data', 'guests.json');

// ── Guest list (loaded from data/guests.json) ─────────────────────

let GUESTS = {};
try {
  GUESTS = JSON.parse(fs.readFileSync(GUESTS_FILE, 'utf8'));
  console.log('Loaded ' + Object.keys(GUESTS).length + ' guests from data/guests.json');
} catch (err) {
  console.error('WARNING: Could not load data/guests.json — no guest validation active.');
  console.error('  Create it with: { "slug": "Nombre" } pairs.');
}

// ── Security headers ─────────────────────────────────────────

app.use((_req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '0',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
  });
  next();
});

app.use(express.json({ limit: '1kb' }));

// ── Cookie parser (no dependencies) ──────────────────────────

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach(pair => {
    const [name, ...rest] = pair.trim().split('=');
    if (name) cookies[name.trim()] = decodeURIComponent(rest.join('=').trim());
  });
  return cookies;
}

// ── Static files ──────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '7d' }));

// ── Rate limiting (in-memory, per IP) ────────────────────────

const rateMap = new Map();
const RATE_WINDOW = 60_000;   // 1 minute
const RATE_MAX = 10;          // max 10 RSVP requests per minute per IP

function rateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const entry = rateMap.get(ip);

  if (!entry || now - entry.start > RATE_WINDOW) {
    rateMap.set(ip, { start: now, count: 1 });
    return next();
  }

  entry.count++;
  if (entry.count > RATE_MAX) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  next();
}

// Cleanup stale entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateMap) {
    if (now - entry.start > RATE_WINDOW) rateMap.delete(ip);
  }
}, 300_000);

// ── Helpers ──────────────────────────────────────────────────

function readRsvps() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function writeRsvps(data) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ── ICS Generation ───────────────────────────────────────────

function generateICS() {
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Emiliano//Invitacion//ES',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    'BEGIN:VTIMEZONE',
    'TZID:America/Argentina/Buenos_Aires',
    'BEGIN:STANDARD',
    'DTSTART:19700101T000000',
    'TZOFFSETFROM:-0300',
    'TZOFFSETTO:-0300',
    'END:STANDARD',
    'END:VTIMEZONE',
    'BEGIN:VEVENT',
    'UID:cumple-emiliano-2026@asterion.me',
    'DTSTAMP:20260406T000000Z',
    'DTSTART;TZID=America/Argentina/Buenos_Aires:20260411T210000',
    'DTEND;TZID=America/Argentina/Buenos_Aires:20260412T030000',
    'SUMMARY:Cumple de Emiliano 🎉',
    'LOCATION:Rumania 100\\, Berisso',
    'DESCRIPTION:Cenita chill\\, con música\\, tragos y juegos de mesa 🎲🍷',
    'STATUS:CONFIRMED',
    'END:VEVENT',
    'END:VCALENDAR',
  ];
  return lines.join('\r\n');
}

// ── Routes ───────────────────────────────────────────────────

// RSVP API
app.post('/api/rsvp', rateLimit, (req, res) => {
  const { slug, attending } = req.body;
  if (!slug || typeof slug !== 'string' || slug.length > 100) {
    return res.status(400).json({ error: 'Invalid slug' });
  }
  const sanitizedSlug = slug.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
  if (!sanitizedSlug || !GUESTS[sanitizedSlug]) {
    return res.status(404).json({ error: 'Invalid guest' });
  }

  // Device lock: check cookie
  const cookies = parseCookies(req);
  const lockedSlug = cookies.rsvp_slug;
  if (lockedSlug && lockedSlug !== sanitizedSlug) {
    return res.status(403).json({ error: 'locked', lockedTo: lockedSlug });
  }

  const rsvps = readRsvps();

  // Prevent spam: cap total unique slugs
  if (!rsvps[sanitizedSlug] && Object.keys(rsvps).length >= MAX_RSVPS) {
    return res.status(429).json({ error: 'Too many RSVPs' });
  }

  rsvps[sanitizedSlug] = {
    attending: !!attending,
    updatedAt: new Date().toISOString(),
  };
  writeRsvps(rsvps);

  // Lock device to this slug (cookie expires in 30 days)
  res.set('Set-Cookie', 'rsvp_slug=' + sanitizedSlug + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000');
  res.json({ ok: true, attending: !!attending });
});

app.get('/api/rsvp/:slug', (req, res) => {
  const sanitizedSlug = req.params.slug.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
  if (!GUESTS[sanitizedSlug]) return res.status(404).json({ error: 'Invalid guest' });
  const cookies = parseCookies(req);
  const lockedSlug = cookies.rsvp_slug;
  const rsvps = readRsvps();
  const entry = rsvps[sanitizedSlug];
  res.json({
    attending: entry ? entry.attending : null,
    locked: !!(lockedSlug && lockedSlug !== sanitizedSlug),
    lockedTo: (lockedSlug && lockedSlug !== sanitizedSlug) ? lockedSlug : null,
  });
});

// Calendar download
app.get('/api/calendar', (_req, res) => {
  const ics = generateICS();
  res.set({
    'Content-Type': 'text/calendar; charset=utf-8',
    'Content-Disposition': 'attachment; filename="cumple-emiliano.ics"',
  });
  res.send(ics);
});

// Admin: ver RSVPs (protected by ADMIN_KEY env var)
app.get('/admin/rsvps', (req, res) => {
  if (ADMIN_KEY && req.query.key !== ADMIN_KEY) {
    return res.status(401).send('Unauthorized');
  }
  const rsvps = readRsvps();
  const entries = Object.entries(rsvps)
    .map(([slug, data]) => ({ slug, ...data }))
    .sort((a, b) => (a.slug > b.slug ? 1 : -1));

  const confirmed = entries.filter(e => e.attending);
  const declined = entries.filter(e => !e.attending);

  res.send(`<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RSVPs — Cumple de Emiliano</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; background: #0f0f0f; color: #e0e0e0; }
  h1 { font-size: 1.4rem; }
  h2 { font-size: 1.1rem; margin-top: 2rem; }
  .count { color: #aaa; font-weight: normal; }
  ul { list-style: none; padding: 0; }
  li { padding: .4rem 0; border-bottom: 1px solid #222; }
  .slug { font-weight: 600; }
  .date { color: #888; font-size: .85rem; margin-left: .5rem; }
</style></head><body>
<h1>RSVPs</h1>
<h2>✅ Confirmados <span class="count">(${confirmed.length})</span></h2>
<ul>${confirmed.map(e => `<li><span class="slug">${escapeHtml(GUESTS[e.slug] || e.slug)}</span><span class="date">${e.updatedAt}</span></li>`).join('')}</ul>
<h2>❌ Declinaron <span class="count">(${declined.length})</span></h2>
<ul>${declined.map(e => `<li><span class="slug">${escapeHtml(GUESTS[e.slug] || e.slug)}</span><span class="date">${e.updatedAt}</span></li>`).join('')}</ul>
</body></html>`);
});

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Main invitation page ─────────────────────────────────────

app.get('/:slug', (req, res) => {
  const slug = req.params.slug.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
  if (!slug || !GUESTS[slug]) return res.status(404).send('Not found');
  res.send(renderPage(slug, GUESTS[slug]));
});

// Root — show page without RSVP ability
app.get('/', (_req, res) => {
  res.send(renderPage(null, null));
});

function renderPage(slug, guestName) {
  const isGuest = !!(slug && guestName);
  const safeGuestName = isGuest ? escapeHtml(guestName.split(' ')[0]) : '';
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>¡Estás invitado/a! — Cumple de Emiliano</title>
<meta name="description" content="Invitación al cumpleaños de Emiliano Lamas — 11 de abril 2026">
<meta property="og:title" content="Cumple de Emiliano 🎉">
<meta property="og:description" content="Cenita chill, con música, tragos y juegos de mesa — Sábado 11 de abril, 21 hs">
<meta property="og:image" content="/thumbnail.webp">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fredoka:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #0e0e12;
  --card: rgba(255,255,255,0.04);
  --card-border: rgba(255,255,255,0.08);
  --text: #e8e6e3;
  --text-muted: #9a9590;
  --accent: #f4a261;
  --accent-glow: rgba(244,162,97,0.15);
  --confirm-green: #6bcb77;
  --confirm-green-glow: rgba(107,203,119,0.15);
  --decline-red: #e76f6f;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

html {
  background: var(--bg);
  color: var(--text);
  font-family: 'Fredoka', system-ui, -apple-system, sans-serif;
  -webkit-font-smoothing: antialiased;
  scroll-behavior: smooth;
}

body {
  min-height: 100dvh;
  overflow-x: hidden;
}

canvas#confetti {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 0;
}

.page {
  position: relative;
  z-index: 1;
  max-width: 480px;
  margin: 0 auto;
  padding: 3rem 1.5rem 4rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2rem;
}

/* ── Hero ─────────────────────────────── */

.hero {
  text-align: center;
  padding-top: 2rem;
  padding-bottom: 0.5rem;
}

.hero .emoji-top {
  font-size: 3.2rem;
  display: block;
  margin-bottom: 1rem;
  animation: float 3s ease-in-out infinite;
}

@keyframes float {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-8px); }
}

.hero h1 {
  font-family: 'Fredoka', sans-serif;
  font-weight: 700;
  font-size: clamp(2.8rem, 12vw, 4.5rem);
  line-height: 1.05;
  letter-spacing: -0.03em;
  margin-bottom: .2rem;
  background: linear-gradient(135deg, #f4a261 0%, #e76f51 50%, #f4a261 100%);
  background-size: 200% 200%;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  animation: shimmer 4s ease-in-out infinite;
}

@keyframes shimmer {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

.hero .subtitle {
  margin-top: .8rem;
  font-size: 1.2rem;
  color: var(--text-muted);
  font-weight: 400;
  letter-spacing: 0.02em;
}

/* ── Cards ────────────────────────────── */

.card {
  width: 100%;
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: 16px;
  padding: 1.5rem;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.card h2 {
  font-size: 1rem;
  font-weight: 600;
  color: var(--accent);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 1rem;
}

/* ── Details ──────────────────────────── */

.details-grid {
  display: flex;
  flex-direction: column;
  gap: .9rem;
}

.detail-row {
  display: flex;
  align-items: flex-start;
  gap: .75rem;
}

.detail-row .icon {
  font-size: 1.3rem;
  flex-shrink: 0;
  width: 1.8rem;
  text-align: center;
}

.detail-row .label {
  font-size: .8rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.detail-row .value {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text);
  line-height: 1.3;
}

.detail-row .value a {
  color: var(--accent);
  text-decoration: none;
  border-bottom: 1px dashed rgba(244,162,97,0.4);
  padding-bottom: 1px;
  transition: border-color .2s;
}

.detail-row .value a:hover {
  border-color: var(--accent);
}

.detail-row .value a::after {
  content: ' ↗';
  font-size: .8em;
  opacity: .6;
}

/* ── Vibe ─────────────────────────────── */

.vibe {
  text-align: center;
  font-size: 1.15rem;
  color: var(--text);
  font-weight: 400;
  line-height: 1.5;
  padding: .5rem 0;
}

.vibe .emojis {
  display: block;
  font-size: 1.6rem;
  margin-top: .5rem;
  letter-spacing: .2rem;
}

/* ── Games ────────────────────────────── */

.games-list {
  list-style: none;
  display: flex;
  flex-wrap: wrap;
  gap: .5rem;
}

.games-list li {
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 100px;
  padding: .4rem .9rem;
  font-size: .88rem;
  color: var(--text);
  white-space: nowrap;
  transition: background .2s, border-color .2s;
}

.games-list li:hover {
  background: rgba(244,162,97,0.1);
  border-color: rgba(244,162,97,0.25);
}

.bring-game {
  margin-top: .75rem;
  font-size: .9rem;
  color: var(--text-muted);
  text-align: center;
}

/* ── Buttons ──────────────────────────── */

.actions {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: .75rem;
}

.btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: .5rem;
  width: 100%;
  padding: 1rem;
  border: none;
  border-radius: 14px;
  font-family: 'Fredoka', sans-serif;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all .25s cubic-bezier(.4,0,.2,1);
  text-decoration: none;
}

.btn-confirm {
  background: var(--confirm-green);
  color: #0e0e12;
  box-shadow: 0 0 0 0 var(--confirm-green-glow);
}

.btn-confirm:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 30px var(--confirm-green-glow);
}

.btn-confirm.confirmed {
  background: transparent;
  color: var(--confirm-green);
  border: 2px solid var(--confirm-green);
}

.btn-decline {
  background: transparent;
  color: var(--text-muted);
  border: 1px solid var(--card-border);
}

.btn-decline:hover {
  border-color: var(--decline-red);
  color: var(--decline-red);
}

.btn-decline.declined {
  border-color: var(--decline-red);
  color: var(--decline-red);
  background: rgba(231,111,111,0.08);
}

.btn-calendar {
  background: rgba(255,255,255,0.06);
  color: var(--text);
  border: 1px solid var(--card-border);
}

.btn-calendar:hover {
  background: var(--accent-glow);
  border-color: var(--accent);
  color: var(--accent);
  transform: translateY(-1px);
}

/* ── Status message ───────────────────── */

.status-msg {
  text-align: center;
  font-size: .9rem;
  min-height: 1.4rem;
  transition: opacity .3s;
}

.status-msg.green { color: var(--confirm-green); }
.status-msg.red { color: var(--decline-red); }

/* ── Footer ───────────────────────────── */

.footer {
  text-align: center;
  font-size: .78rem;
  color: rgba(255,255,255,0.2);
  padding-top: 1rem;
}

/* ── Responsive ───────────────────────── */

@media (max-width: 380px) {
  .page { padding: 2rem 1rem 3rem; gap: 1.5rem; }
  .card { padding: 1.2rem; }
  .games-list li { font-size: .82rem; padding: .35rem .7rem; }
}
</style>
</head>
<body>
<canvas id="confetti"></canvas>

<div class="page">

  <!-- Hero -->
  <div class="hero">
    <span class="emoji-top">🎂</span>
    <h1>Cumple de<br>Emiliano</h1>
    <p class="subtitle">${isGuest ? `¡${safeGuestName}, estás invitado/a!` : '¡Estás invitado/a!'}</p>
  </div>

  <!-- Details card -->
  <div class="card">
    <h2>Detalles</h2>
    <div class="details-grid">
      <div class="detail-row">
        <span class="icon">📅</span>
        <div>
          <div class="label">Fecha</div>
          <div class="value">Sábado 11 de abril, 2026</div>
        </div>
      </div>
      <div class="detail-row">
        <span class="icon">🕘</span>
        <div>
          <div class="label">Horario</div>
          <div class="value">21:00 hs → 03:00 hs</div>
        </div>
      </div>
      <div class="detail-row">
        <span class="icon">📍</span>
        <div>
          <div class="label">Dirección</div>
          <div class="value">
            <a href="https://maps.google.com/?q=Rumania+100+Berisso" target="_blank" rel="noopener">
              Rumania 100, Berisso
            </a>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Vibe -->
  <p class="vibe">
    Cenita chill, con música, tragos y juegos de mesa
    <span class="emojis">🎲 🍷 🎶</span>
  </p>

  <!-- Games card -->
  <div class="card">
    <h2>Juegos 🎮</h2>
    <ul class="games-list">
      <li>Pistas cruzadas</li>
      <li>Exploding Kittens</li>
      <li>Amigos de mierda</li>
      <li>El HDP</li>
      <li>Stop</li>
      <li>Werewolf Party</li>
      <li>Desconectados En Palabras</li>
      <li>Destapados En Palabras</li>
      <li>Cartas españolas y francesas</li>
    </ul>
    <p class="bring-game">¡Si tenés algún juego copado, traelo! 🙌</p>
  </div>

  <!-- Actions -->
  <div class="actions">
${isGuest ? `    <button class="btn btn-confirm" id="btnConfirm" onclick="rsvp(true)">
      <span>✅</span> <span>Confirmar asistencia</span>
    </button>
    <button class="btn btn-decline" id="btnDecline" onclick="rsvp(false)">
      <span>No puedo ir 😢</span>
    </button>
    <p class="status-msg" id="statusMsg"></p>` : `    <p class="status-msg" style="color: var(--text-muted);">Para confirmar asistencia, usá tu link personal</p>`}
    <a class="btn btn-calendar" href="/api/calendar" download="cumple-emiliano.ics">
      <span>📆</span> <span>Añadir al calendario</span>
    </a>
  </div>

  <p class="footer">Con cariño, Emiliano 💛</p>

</div>

<script>
// ── RSVP Logic ───────────────────────────────────────────────

const SLUG = ${isGuest ? "'" + slug + "'" : 'null'};
const btnConfirm = document.getElementById('btnConfirm');
const btnDecline = document.getElementById('btnDecline');
const statusMsg = document.getElementById('statusMsg');
let currentState = null;

if (SLUG && btnConfirm) {

// Load saved state
fetch('/api/rsvp/' + SLUG)
  .then(r => r.json())
  .then(d => {
    if (d.locked) {
      // Device already confirmed for a different person
      btnConfirm.disabled = true;
      btnDecline.disabled = true;
      btnConfirm.innerHTML = '<span>🔒</span> <span>Ya confirmaste desde otro link</span>';
      btnConfirm.style.opacity = '0.5';
      btnConfirm.style.cursor = 'not-allowed';
      btnDecline.style.display = 'none';
      showStatus('Este dispositivo ya fue usado para confirmar con otro link', 'red');
      return;
    }
    if (d.attending !== null) {
      currentState = d.attending;
      updateButtons();
    }
  })
  .catch(() => {});

function rsvp(attending) {
  // Toggle off if same button
  if (currentState === attending) return;

  fetch('/api/rsvp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ slug: SLUG, attending }),
  })
    .then(r => {
      if (r.status === 403) {
        return r.json().then(d => {
          showStatus('Este dispositivo ya confirmó con otro link (' + d.lockedTo + ')', 'red');
          return null;
        });
      }
      return r.json();
    })
    .then(d => {
      if (!d || !d.ok) return;
      currentState = d.attending;
      updateButtons();
      showStatus(d.attending ? '¡Genial, te esperamos! 🎉' : 'Una pena, te vamos a extrañar 💔',
                 d.attending ? 'green' : 'red');
    })
    .catch(() => showStatus('Error al confirmar, intentá de nuevo', 'red'));
}

function updateButtons() {
  btnConfirm.classList.toggle('confirmed', currentState === true);
  btnDecline.classList.toggle('declined', currentState === false);

  if (currentState === true) {
    btnConfirm.innerHTML = '<span>✅</span> <span>¡Confirmado!</span>';
    btnDecline.innerHTML = '<span>Cancelar asistencia</span>';
  } else if (currentState === false) {
    btnConfirm.innerHTML = '<span>✅</span> <span>Confirmar asistencia</span>';
    btnDecline.innerHTML = '<span>No voy 😢</span>';
  } else {
    btnConfirm.innerHTML = '<span>✅</span> <span>Confirmar asistencia</span>';
    btnDecline.innerHTML = '<span>No puedo ir 😢</span>';
  }
}

function showStatus(msg, color) {
  statusMsg.textContent = msg;
  statusMsg.className = 'status-msg ' + color;
  setTimeout(() => { statusMsg.style.opacity = '0'; }, 3000);
  setTimeout(() => {
    statusMsg.textContent = '';
    statusMsg.style.opacity = '1';
  }, 3500);
}

} // end if (SLUG && btnConfirm)

// ── Confetti Canvas ──────────────────────────────────────────

(function () {
  const canvas = document.getElementById('confetti');
  const ctx = canvas.getContext('2d');

  const COLORS = ['#f4a261', '#e76f51', '#6bcb77', '#48bfe3', '#e76f6f', '#f0c27f', '#c084fc', '#ffd166', '#ff6b6b'];
  const PARTICLE_COUNT = 100;
  const particles = [];

  let w, h;

  function resize() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
  }

  window.addEventListener('resize', resize);
  resize();

  class Particle {
    constructor() { this.reset(true); }

    reset(init) {
      this.x = Math.random() * w;
      this.y = init ? Math.random() * h : -10 - Math.random() * 40;
      this.size = 6 + Math.random() * 10;
      this.speedY = 0.4 + Math.random() * 1.0;
      this.speedX = (Math.random() - 0.5) * 0.8;
      this.rotation = Math.random() * 360;
      this.rotationSpeed = (Math.random() - 0.5) * 4;
      this.color = COLORS[Math.floor(Math.random() * COLORS.length)];
      this.opacity = 0.45 + Math.random() * 0.4;
      this.shape = Math.random() > 0.4 ? 'rect' : 'circle';
      // Gentle wobble
      this.wobbleAmp = 0.5 + Math.random() * 0.8;
      this.wobbleSpeed = 0.015 + Math.random() * 0.025;
      this.wobbleOffset = Math.random() * Math.PI * 2;
      this.tick = 0;
    }

    update() {
      this.tick++;
      this.y += this.speedY;
      this.x += this.speedX + Math.sin(this.tick * this.wobbleSpeed + this.wobbleOffset) * this.wobbleAmp;
      this.rotation += this.rotationSpeed;

      if (this.y > h + 20) this.reset(false);
      if (this.x < -20) this.x = w + 20;
      if (this.x > w + 20) this.x = -20;
    }

    draw() {
      ctx.save();
      ctx.translate(this.x, this.y);
      ctx.rotate((this.rotation * Math.PI) / 180);
      ctx.globalAlpha = this.opacity;
      ctx.fillStyle = this.color;

      if (this.shape === 'rect') {
        ctx.fillRect(-this.size / 2, -this.size / 4, this.size, this.size / 2);
      } else {
        ctx.beginPath();
        ctx.arc(0, 0, this.size / 2, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.restore();
    }
  }

  for (let i = 0; i < PARTICLE_COUNT; i++) {
    particles.push(new Particle());
  }

  // Respect reduced motion
  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function loop() {
    ctx.clearRect(0, 0, w, h);
    for (const p of particles) {
      p.update();
      p.draw();
    }
    if (!prefersReduced) requestAnimationFrame(loop);
  }

  if (!prefersReduced) {
    requestAnimationFrame(loop);
  }
})();
</script>
</body>
</html>`;
}

// ── Start ────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('🎉 Invitation server running at http://localhost:' + PORT);
  console.log('   Example: http://localhost:' + PORT + '/victorias');
  console.log('   Admin:   http://localhost:' + PORT + '/admin/rsvps');
});
