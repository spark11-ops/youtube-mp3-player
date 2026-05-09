require('dotenv').config({ quiet: true });

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const SESSION_COOKIE = 'ytmp3_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

if (!process.env.SESSION_SECRET) {
    console.warn('SESSION_SECRET is not set. Existing sign-in sessions will expire when the server restarts.');
}

ensureDataFiles();

const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://${req.headers.host}`);

        if (url.pathname.startsWith('/api/')) {
            await handleApi(req, res, url);
            return;
        }

        serveStatic(url.pathname, res);
    } catch (error) {
        const statusCode = error.statusCode || 500;
        if (statusCode >= 500) {
            console.error(error);
        }
        sendJson(res, statusCode, { error: error.message || 'Unexpected server error' });
    }
});

if (require.main === module) {
    server.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
    });
}

async function handleApi(req, res, url) {
    if (req.method === 'GET' && url.pathname === '/api/auth/me') {
        const user = getAuthenticatedUser(req);
        sendJson(res, 200, { user: user ? publicUser(user) : null });
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/signup') {
        const body = await readJsonBody(req);
        const user = createUser(body.email, body.password);
        setSessionCookie(res, createSession(user.id));
        sendJson(res, 201, { user: publicUser(user) });
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/signin') {
        const body = await readJsonBody(req);
        const user = verifyUser(body.email, body.password);
        setSessionCookie(res, createSession(user.id));
        sendJson(res, 200, { user: publicUser(user) });
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/signout') {
        deleteSession(req);
        clearSessionCookie(res);
        sendJson(res, 200, { ok: true });
        return;
    }

    if (req.method === 'GET' && url.pathname === '/api/playlist') {
        const user = getAuthenticatedUser(req);
        if (!user) {
            sendJson(res, 401, { error: 'Please sign in to load playlists.' });
            return;
        }

        await handlePlaylist(url, res);
        return;
    }

    sendJson(res, 404, { error: 'API route not found' });
}

async function handlePlaylist(url, res) {
    const playlistId = url.searchParams.get('id');
    if (!playlistId || !/^[a-zA-Z0-9_-]+$/.test(playlistId)) {
        sendJson(res, 400, { error: 'Missing or invalid playlist ID' });
        return;
    }

    if (!YOUTUBE_API_KEY) {
        sendJson(res, 500, { error: 'YouTube API key is not configured on the server.' });
        return;
    }

    const playlistUrl = new URL('https://www.googleapis.com/youtube/v3/playlists');
    playlistUrl.searchParams.set('part', 'snippet');
    playlistUrl.searchParams.set('id', playlistId);
    playlistUrl.searchParams.set('key', YOUTUBE_API_KEY);

    const playlistResponse = await fetchJson(playlistUrl);
    if (!playlistResponse.items || playlistResponse.items.length === 0) {
        sendJson(res, 404, { error: 'Playlist not found' });
        return;
    }

    const title = playlistResponse.items[0].snippet.title;
    const allItems = [];
    let nextPageToken = '';

    do {
        const itemsUrl = new URL('https://www.googleapis.com/youtube/v3/playlistItems');
        itemsUrl.searchParams.set('part', 'snippet');
        itemsUrl.searchParams.set('maxResults', '50');
        itemsUrl.searchParams.set('playlistId', playlistId);
        itemsUrl.searchParams.set('key', YOUTUBE_API_KEY);

        if (nextPageToken) {
            itemsUrl.searchParams.set('pageToken', nextPageToken);
        }

        const data = await fetchJson(itemsUrl);
        allItems.push(...(data.items || []));
        nextPageToken = data.nextPageToken || '';
    } while (nextPageToken);

    const items = allItems
        .filter((item) => item.snippet && item.snippet.resourceId && item.snippet.resourceId.videoId)
        .map((item) => {
            const thumbnails = item.snippet.thumbnails || {};
            return {
                id: item.snippet.resourceId.videoId,
                title: item.snippet.title,
                channel: item.snippet.videoOwnerChannelTitle || item.snippet.channelTitle || 'Unknown channel',
                thumbnail: (thumbnails.medium || thumbnails.default || {}).url || ''
            };
        });

    sendJson(res, 200, { title, items });
}

async function fetchJson(url) {
    const response = await fetch(url);
    const data = await response.json().catch(() => ({}));

    if (!response.ok || data.error) {
        const message = data.error && data.error.message ? data.error.message : 'YouTube request failed';
        throw new Error(message);
    }

    return data;
}

function createUser(email, password) {
    const normalizedEmail = normalizeEmail(email);
    validatePassword(password);

    const users = readJsonFile(USERS_FILE, []);
    if (users.some((user) => user.email === normalizedEmail)) {
        throw httpError(409, 'An account already exists for this email.');
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(password, salt);
    const user = {
        id: crypto.randomUUID(),
        email: normalizedEmail,
        passwordHash,
        salt,
        createdAt: new Date().toISOString()
    };

    users.push(user);
    writeJsonFile(USERS_FILE, users);
    return user;
}

function verifyUser(email, password) {
    const normalizedEmail = normalizeEmail(email);
    const users = readJsonFile(USERS_FILE, []);
    const user = users.find((candidate) => candidate.email === normalizedEmail);

    if (!user || hashPassword(password, user.salt) !== user.passwordHash) {
        throw httpError(401, 'Invalid email or password.');
    }

    return user;
}

function createSession(userId) {
    const sessions = readJsonFile(SESSIONS_FILE, []);
    const expiresAt = Date.now() + SESSION_TTL_MS;
    const token = crypto.randomBytes(32).toString('hex');
    const session = {
        id: crypto.randomUUID(),
        userId,
        tokenHash: signToken(token),
        expiresAt
    };

    const activeSessions = sessions.filter((candidate) => candidate.expiresAt > Date.now());
    activeSessions.push(session);
    writeJsonFile(SESSIONS_FILE, activeSessions);

    return `${session.id}.${token}`;
}

function getAuthenticatedUser(req) {
    const rawSession = parseCookies(req.headers.cookie || '')[SESSION_COOKIE];
    if (!rawSession) return null;

    const [sessionId, token] = rawSession.split('.');
    if (!sessionId || !token) return null;

    const sessions = readJsonFile(SESSIONS_FILE, []);
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session || session.expiresAt <= Date.now()) return null;
    if (!safeEqual(session.tokenHash, signToken(token))) return null;

    const users = readJsonFile(USERS_FILE, []);
    return users.find((user) => user.id === session.userId) || null;
}

function deleteSession(req) {
    const rawSession = parseCookies(req.headers.cookie || '')[SESSION_COOKIE];
    if (!rawSession) return;

    const [sessionId] = rawSession.split('.');
    const sessions = readJsonFile(SESSIONS_FILE, []);
    writeJsonFile(SESSIONS_FILE, sessions.filter((session) => session.id !== sessionId));
}

function setSessionCookie(res, sessionValue) {
    const parts = [
        `${SESSION_COOKIE}=${sessionValue}`,
        'HttpOnly',
        'Path=/',
        'SameSite=Lax',
        `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
    ];

    if (process.env.NODE_ENV === 'production') {
        parts.push('Secure');
    }

    res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res) {
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
}

function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 210000, 64, 'sha512').toString('hex');
}

function signToken(token) {
    return crypto.createHmac('sha256', SESSION_SECRET).update(token).digest('hex');
}

function safeEqual(a, b) {
    const first = Buffer.from(a);
    const second = Buffer.from(b);
    return first.length === second.length && crypto.timingSafeEqual(first, second);
}

function normalizeEmail(email) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
        throw httpError(400, 'Enter a valid email address.');
    }
    return normalizedEmail;
}

function validatePassword(password) {
    if (String(password || '').length < 8) {
        throw httpError(400, 'Password must be at least 8 characters.');
    }
}

function publicUser(user) {
    return {
        id: user.id,
        email: user.email
    };
}

async function readJsonBody(req) {
    const chunks = [];

    for await (const chunk of req) {
        chunks.push(chunk);
        if (Buffer.concat(chunks).length > 1024 * 1024) {
            throw httpError(413, 'Request body is too large.');
        }
    }

    if (!chunks.length) return {};

    try {
        return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
        throw httpError(400, 'Invalid JSON body.');
    }
}

function serveStatic(requestPath, res) {
    const safePath = requestPath === '/' ? '/index.html' : decodeURIComponent(requestPath);
    const filePath = path.normalize(path.join(ROOT_DIR, safePath));

    const isInsideRoot = filePath === ROOT_DIR || filePath.startsWith(`${ROOT_DIR}${path.sep}`);
    if (!isInsideRoot || filePath.includes(`${path.sep}data${path.sep}`) || filePath.includes(`${path.sep}.env`)) {
        sendText(res, 403, 'Forbidden');
        return;
    }

    fs.readFile(filePath, (error, content) => {
        if (error) {
            sendText(res, 404, 'Not found');
            return;
        }

        const contentType = mimeTypes[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
        res.writeHead(200, {
            'Content-Type': contentType,
            'Cache-Control': 'no-store'
        });
        res.end(content);
    });
}

function sendJson(res, statusCode, payload) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(payload));
}

function sendText(res, statusCode, message) {
    res.writeHead(statusCode, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(message);
}

function parseCookies(cookieHeader) {
    return cookieHeader.split(';').reduce((cookies, pair) => {
        const [name, ...valueParts] = pair.trim().split('=');
        if (name) {
            cookies[name] = decodeURIComponent(valueParts.join('='));
        }
        return cookies;
    }, {});
}

function readJsonFile(filePath, fallback) {
    try {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
        return fallback;
    }
}

function writeJsonFile(filePath, value) {
    fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function ensureDataFiles() {
    fs.mkdirSync(DATA_DIR, { recursive: true });

    if (!fs.existsSync(USERS_FILE)) {
        writeJsonFile(USERS_FILE, []);
    }

    if (!fs.existsSync(SESSIONS_FILE)) {
        writeJsonFile(SESSIONS_FILE, []);
    }
}

function httpError(statusCode, message) {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
}

process.on('unhandledRejection', (error) => {
    console.error(error);
});

module.exports = { server, PORT };
