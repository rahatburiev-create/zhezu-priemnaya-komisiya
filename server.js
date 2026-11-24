'use strict';

// Сервер ЖезУ без внешних библиотек. Все данные хранятся в UTF-8 файле database.txt.
// Страницы находятся в public, база и резервная копия никогда не выдаются браузеру.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const COOKIE = 'zhezu_session';
const BODY_LIMIT = 16 * 1024;
const RECEIPT_LIMIT = 5 * 1024 * 1024;
const RECEIPT_BODY_LIMIT = 7 * 1024 * 1024;
const MAX_MONEY_MINOR = 99_999_999_999_999;
const SESSION_SECONDS = 12 * 60 * 60;
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };
const STATUS = { new: 'Новое обращение', review: 'На проверке', accepted: 'Документы приняты', enrolled: 'Зачислен' };
const OPTIONS = parseOptions(process.argv.slice(2));
const DB_PATH = path.resolve(ROOT, OPTIONS.db || 'database.txt');
const LOCK_PATH = DB_PATH + '.lock';
const RECEIPTS_PATH = path.resolve(ROOT, OPTIONS.receipts || path.join(path.dirname(DB_PATH), 'receipts'));
let database;
let diskHash = null; // Отпечаток точных байтов для защиты правок, сделанных в Блокноте.
let ownsLock = false;
let server;
let port = integerOption(OPTIONS.port || '8080', 0, 65535);
const counters = new Map();
const configuredOrigin = normalizeOrigin(process.env.ZHEZU_ORIGIN || '');

class ApiError extends Error { constructor(status, message) { super(message); this.status = status; } }
function parseOptions(args) {
  const out = {};
  const booleans = new Set(['setup-admin', 'password-stdin', 'open']);
  const strings = new Set(['db', 'port', 'host', 'login', 'name', 'receipts']);
  for (let i = 0; i < args.length; i++) {
    const key = args[i].startsWith('--') ? args[i].slice(2) : '';
    if (booleans.has(key)) out[key] = true;
    else if (strings.has(key) && i + 1 < args.length && !args[i + 1].startsWith('--')) out[key] = args[++i];
    else throw new Error('Неизвестный параметр запуска: ' + args[i]);
  }
  return out;
}
function integerOption(value, min, max) {
  if (!/^\d+$/.test(String(value)) || Number(value) < min || Number(value) > max) throw new Error('Некорректный номер порта.');
  return Number(value);
}
function normalizeOrigin(value) {
  if (!value) return '';
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('ZHEZU_ORIGIN должен содержать только адрес сайта без пути.');
  return url.origin;
}

// Блокировка не допускает два одновременно работающих сервера с одним файлом.
function acquireLock() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  const create = () => {
    const fd = fs.openSync(LOCK_PATH, 'wx', 0o600);
    try { fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    ownsLock = true;
  };
  try { create(); return; } catch (error) { if (error.code !== 'EEXIST') throw error; }
  // Отдельный эксклюзивный файл сериализует восстановление старой блокировки.
  // Нельзя удалять новую блокировку, которую успел получить другой процесс.
  const recovery = LOCK_PATH + '.recovery';
  let guard;
  try { guard = fs.openSync(recovery, 'wx', 0o600); }
  catch { throw new Error('Блокировка базы уже проверяется другим процессом. Закройте лишний запуск.'); }
  try {
    let owner;
    try { owner = JSON.parse(fs.readFileSync(LOCK_PATH, 'utf8').replace(/^\uFEFF/, '')); }
    catch (error) { if (error.code === 'ENOENT') { create(); return; } throw new Error('Файл блокировки повреждён. Остановите сервер и проверьте ' + LOCK_PATH); }
    if (!Number.isInteger(owner.pid) || owner.pid < 1) throw new Error('Некорректная блокировка базы.');
    try { process.kill(owner.pid, 0); throw new Error('Эта база уже открыта другим сервером.'); }
    catch (probe) { if (probe.code !== 'ESRCH') throw probe; }
    fs.unlinkSync(LOCK_PATH);
    // При гонке обычный запуск может первым создать файл: create() тогда откажет,
    // а чужая новая блокировка останется на месте.
    create();
  } finally { fs.closeSync(guard); fs.unlinkSync(recovery); }
}
function releaseLock() {
  if (!ownsLock) return;
  try { const lock = JSON.parse(fs.readFileSync(LOCK_PATH, 'utf8')); if (lock.pid === process.pid) fs.unlinkSync(LOCK_PATH); }
  catch { /* Блокировку другого процесса не удаляем. */ }
  ownsLock = false;
}
function loadDatabase() {
  if (!fs.existsSync(DB_PATH)) throw new Error('Не найден файл базы ' + DB_PATH + '. Восстановите database.txt из архива. Пустая база автоматически не создаётся.');
  let parsed;
  try { const raw = fs.readFileSync(DB_PATH); diskHash = sha(raw); parsed = JSON.parse(raw.toString('utf8').replace(/^\uFEFF/, '')); }
  catch { throw new Error('В database.txt ошибка JSON. Исправьте файл в Блокноте; исходные данные не изменены.'); }
  if (!parsed || parsed.version !== 1 || !['programs', 'users', 'sessions', 'applicants', 'tasks'].every(key => Array.isArray(parsed[key]))) throw new Error('Некорректная структура базы. Файл не изменён.');
  for (const key of ['programs', 'users', 'sessions', 'applicants', 'tasks']) {
    const ids = new Set();
    for (const item of parsed[key]) {
      if (!item || typeof item !== 'object' || typeof item.id !== 'string' || !item.id || ids.has(item.id)) throw new Error('Проверьте уникальные id в разделе ' + key + '. Файл не изменён.');
      ids.add(item.id);
    }
  }
  const logins = new Set();
  for (const user of parsed.users) {
    if (typeof user.login !== 'string' || !['admin', 'student'].includes(user.role) || typeof user.passwordHash !== 'string' || typeof user.passwordSalt !== 'string') throw new Error('Некорректная запись пользователя. Файл не изменён.');
    const normalized = user.login.trim().toLowerCase();
    if (logins.has(normalized)) throw new Error('Логины пользователей должны быть уникальны. Файл не изменён.');
    logins.add(normalized);
  }
  database = parsed;
  const beforeMigration = JSON.stringify(database);
  normalizeDatabase();
  if (JSON.stringify(database) !== beforeMigration) saveDatabase();
}
function assertDatabaseUnchanged() {
  let current;
  try { current = sha(fs.readFileSync(DB_PATH)); }
  catch { throw new ApiError(409, 'Файл базы был перемещён или изменён извне. Остановите сервер, проверьте database.txt и запустите его заново.'); }
  if (diskHash !== null && current !== diskHash) throw new ApiError(409, 'База изменена в Блокноте или другой программе. Правки сохранены: остановите сервер, проверьте database.txt и запустите его заново.');
}
function saveDatabase() {
  // Не перезаписываем внешние изменения, сделанные после чтения базы.
  assertDatabaseUnchanged();
  const serialized = JSON.stringify(database, null, 2) + '\n';
  const temporary = DB_PATH + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex');
  let fd;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(fd, serialized, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    assertDatabaseUnchanged();
    fs.renameSync(temporary, DB_PATH);
    diskHash = sha(serialized);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}
function mutateDatabase(change) {
  const before = JSON.stringify(database);
  try { const result = change(); saveDatabase(); return result; }
  catch (error) { database = JSON.parse(before); throw error; }
}

function now() { return new Date().toISOString(); }
function id() { return crypto.randomUUID(); }
function sha(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function safeUser(user) { return { id: user.id, login: user.login, name: user.name, role: user.role }; }
function validatePassword(password) { if (typeof password !== 'string' || password.length < 12 || password.length > 128) throw new ApiError(400, 'Пароль должен содержать от 12 до 128 символов.'); }
function validateLogin(login) { if (!/^[a-z0-9][a-z0-9._@+-]{2,79}$/.test(login)) throw new ApiError(400, 'Логин: 3–80 символов, латинские буквы, цифры и . _ @ + - .'); }
async function makeUser(login, name, password, role) {
  validatePassword(password);
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await scrypt(password, salt, 64, SCRYPT);
  return { id: id(), login, name, role, passwordAlgorithm: 'scrypt', passwordSalt: salt, passwordHash: hash.toString('hex'), createdAt: now() };
}
async function passwordMatches(password, user) {
  const salt = user && /^[a-f0-9]{32}$/.test(user.passwordSalt) ? user.passwordSalt : '00000000000000000000000000000000';
  const hash = await scrypt(password, salt, 64, SCRYPT);
  if (!user || user.passwordAlgorithm !== 'scrypt' || !/^[a-f0-9]{128}$/.test(user.passwordHash)) return false;
  return crypto.timingSafeEqual(hash, Buffer.from(user.passwordHash, 'hex'));
}
function sessionToken(req) {
  const raw = req.headers.cookie;
  if (!raw || raw.length > 8192) return null;
  const match = raw.split(';').map(part => part.trim()).find(part => part.startsWith(COOKIE + '='));
  const value = match ? match.slice(COOKIE.length + 1) : '';
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}
function currentUser(req) {
  const token = sessionToken(req);
  if (!token) return null;
  const session = database.sessions.find(item => item.id === sha(token) && Number.isFinite(Date.parse(item.expiresAt)) && Date.parse(item.expiresAt) > Date.now());
  return session ? database.users.find(user => user.id === session.userId) || null : null;
}
function requireUser(req) { const user = currentUser(req); if (!user) throw new ApiError(401, 'Войдите в свою учётную запись.'); return user; }
function requireAdmin(req) { const user = requireUser(req); if (user.role !== 'admin') throw new ApiError(403, 'Доступ разрешён только администрации.'); return user; }
function sessionCookie(token, age) { return COOKIE + '=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + age + (configuredOrigin.startsWith('https://') ? '; Secure' : ''); }
function newSession(req, res, user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const old = sessionToken(req);
  mutateDatabase(() => {
    database.sessions = database.sessions.filter(item => Date.parse(item.expiresAt) > Date.now() && (!old || item.id !== sha(old)));
    database.sessions.push({ id: sha(token), userId: user.id, createdAt: now(), expiresAt: new Date(Date.now() + SESSION_SECONDS * 1000).toISOString() });
  });
  res.setHeader('Set-Cookie', sessionCookie(token, SESSION_SECONDS));
}
function sameOrigin(req) {
  const host = String(req.headers.host || '').toLowerCase();
  const origin = req.headers.origin;
  let allowed;
  if (configuredOrigin) allowed = origin === configuredOrigin && host === new URL(configuredOrigin).host.toLowerCase();
  else allowed = ['127.0.0.1:' + port, 'localhost:' + port, '[::1]:' + port].includes(host) && origin === 'http://' + host;
  if (!allowed) throw new ApiError(403, 'Отправляйте запросы со страницы этого сайта.');
}
function rate(req, kind, maximum, seconds = 600) {
  const window = Math.floor(Date.now() / (seconds * 1000));
  const key = kind + ':' + req.socket.remoteAddress;
  if (counters.size > 10000) for (const [k, item] of counters) if (item.window < window) counters.delete(k);
  let item = counters.get(key);
  if (!item || item.window !== window) { item = { window, count: 0 }; counters.set(key, item); }
  if (++item.count > maximum) throw new ApiError(429, 'Слишком много попыток. Подождите несколько минут.');
}
function readJson(req, limit = BODY_LIMIT) {
  if (String(req.headers['content-type'] || '').toLowerCase().split(';')[0].trim() !== 'application/json') throw new ApiError(415, 'Используйте JSON.');
  if (req.headers['content-length'] && (!/^\d+$/.test(req.headers['content-length']) || Number(req.headers['content-length']) > limit)) throw new ApiError(413, 'Слишком большой запрос.');
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [], failed = false;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) { if (!failed) reject(new ApiError(413, 'Слишком большой запрос.')); failed = true; chunks = []; }
      else if (!failed) chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) return;
      try { const body = JSON.parse(Buffer.concat(chunks).toString('utf8')); if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error(); resolve(body); }
      catch { reject(new ApiError(400, 'Не удалось прочитать форму.')); }
    });
    req.on('error', () => reject(new ApiError(400, 'Соединение прервано.')));
  });
}
function fields(body, allowed) { if (Object.keys(body).some(key => !allowed.includes(key))) throw new ApiError(400, 'Форма содержит неподдерживаемые поля.'); }
function text(body, key, max, required = false, trim = true) {
  if (body[key] === undefined || body[key] === null) { if (required) throw new ApiError(400, 'Заполните поле: ' + key); return ''; }
  if (typeof body[key] !== 'string') throw new ApiError(400, 'Проверьте поле: ' + key);
  const value = trim ? body[key].trim() : body[key];
  if (value.length > max || (required && !value)) throw new ApiError(400, 'Проверьте поле: ' + key);
  return value;
}
function applicantValues(body, admin, previous = null, patch = body) {
  const name = text(body, 'name', 120, true); if (name.length < 2) throw new ApiError(400, 'Укажите имя и фамилию.');
  const phone = text(body, 'phone', 40), email = text(body, 'email', 180);
  if (phone && !/^[+\d\s().-]{5,40}$/.test(phone)) throw new ApiError(400, 'Проверьте номер телефона.');
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new ApiError(400, 'Проверьте электронную почту.');
  let program = text(body, 'program', 255), level = admin ? text(body, 'level', 40) || 'Бакалавриат' : 'Бакалавриат';
  if (!admin) {
    const programId = text(body, 'programId', 80);
    const selected = programId ? database.programs.find(item => item.id === programId) : database.programs.find(item => item.nameRu === program || item.nameKz === program);
    if (programId && !selected) throw new ApiError(400, 'Выберите программу из каталога.');
    if (selected) { program = selected.nameRu || selected.nameKz; level = selected.level === 'master' || selected.level === 'Магистратура' ? 'Магистратура' : 'Бакалавриат'; }
  }
  if (!['Бакалавриат', 'Магистратура'].includes(level)) throw new ApiError(400, 'Проверьте уровень обучения.');
  const status = admin ? text(body, 'status', 20) || 'new' : 'new';
  if (!Object.hasOwn(STATUS, status)) throw new ApiError(400, 'Проверьте статус.');
  const score = admin && body.score !== undefined ? body.score : null;
  if (score !== null && (!Number.isInteger(score) || score < 0 || score > 140)) throw new ApiError(400, 'Баллы: целое число от 0 до 140.');
  const funding = admin ? text(body, 'funding', 20) || 'undecided' : 'undecided';
  if (!['undecided', 'grant', 'paid'].includes(funding)) throw new ApiError(400, 'Проверьте основу финансирования.');
  const tuitionMinor = moneyMinor(admin ? body.tuitionTotal ?? 0 : 0, 'Стоимость обучения');
  if (funding !== 'paid' && tuitionMinor !== 0) throw new ApiError(400, 'Стоимость платного обучения указывается только для платной основы.');
  let documents;
  if (admin && body.documents !== undefined) documents = documentValues(body.documents, funding, previous?.documents);
  else documents = documentValues(defaultDocuments(admin ? body.docs : undefined, funding), funding, previous?.documents, false);
  // Старый интерфейс с пятью флажками продолжает работать, не сбрасывая новые документы.
  if (admin && Object.hasOwn(patch, 'docs') && !Object.hasOwn(patch, 'documents')) {
    validateLegacyDocs(patch.docs);
    documents = documents.map(item => {
      const index = LEGACY_DOCUMENT_IDS.indexOf(item.id);
      if (index < 0) return item;
      const received = patch.docs[index];
      return { ...item, received, receivedAt: received ? item.receivedAt || (previous?.documents?.find(d => d.id === item.id)?.received ? '' : today()) : '' };
    });
  }
  const installmentPlan = admin ? planValues(body.installmentPlan ?? [], funding, tuitionMinor) : [];
  const values = { name, phone, email, program, level, message: text(body, 'message', 2000), score, status, documents, docs: legacyDocs(documents), note: admin ? text(body, 'note', 5000) : '', funding, tuitionTotal: fromMinor(tuitionMinor), installmentPlan };
  for (const key of INTAKE_TEXT_FIELDS) values[key] = admin ? text(body, key, key === 'priorEducation' || key === 'admissionBasis' ? 500 : 120) : '';
  for (const key of INTAKE_DATE_FIELDS) values[key] = admin ? dateValue(body[key], key) : '';
  if (values.birthDate && values.birthDate > today()) throw new ApiError(400, 'Дата рождения не может быть в будущем.');
  if (body.archived !== undefined && admin && typeof body.archived !== 'boolean') throw new ApiError(400, 'Некорректная отметка архива.');
  values.archived = admin ? body.archived ?? false : false;
  return values;
}
const INTAKE_TEXT_FIELDS = ['contractNumber', 'academicYear', 'group', 'applicationNumber', 'enrollmentOrder', 'priorEducation', 'admissionBasis'];
const INTAKE_DATE_FIELDS = ['contractDate', 'applicationDate', 'enrollmentDate', 'birthDate'];
const APPLICANT_FIELDS = ['name', 'phone', 'email', 'program', 'level', 'message', 'score', 'status', 'docs', 'documents', 'note', 'funding', 'tuitionTotal', 'installmentPlan', 'archived', ...INTAKE_TEXT_FIELDS, ...INTAKE_DATE_FIELDS];
const TASK_FIELDS = ['title', 'kind', 'dueAt', 'done'];
// Реквизиты поступления и контроль документов. Исходные пять флажков сохраняются.
const LEGACY_DOCUMENT_IDS = ['statement', 'identity', 'education', 'ent', 'photos'];
const BASE_DOCUMENTS = [
  ['statement', 'Заявление'], ['identity', 'Документ, удостоверяющий личность'],
  ['education', 'Аттестат или диплом'], ['ent', 'Сертификат ЕНТ / КТ (по основанию поступления)'],
  ['medical075', 'Медицинская справка 075/у (при необходимости)'], ['photos', 'Фотографии']
];
function today() {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Almaty', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date());
  const part = type => parts.find(item => item.type === type).value;
  return part('year') + '-' + part('month') + '-' + part('day');
}
function dateValue(value, label, required = false) {
  if (value === undefined || value === null || value === '') { if (required) throw new ApiError(400, 'Укажите дату: ' + label); return ''; }
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value) || value < '1900-01-01' || value > '2199-12-31') throw new ApiError(400, 'Проверьте дату: ' + label);
  const parsed = new Date(value + 'T00:00:00Z');
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) throw new ApiError(400, 'Проверьте дату: ' + label);
  return value;
}
function moneyMinor(value, label = 'Сумма', positive = false) {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new ApiError(400, label + ': укажите число в тенге.');
  const source = String(value);
  if (!/^(0|[1-9]\d{0,11})(?:\.(\d{1,2}))?$/.test(source)) throw new ApiError(400, label + ': допускается не более двух знаков после запятой.');
  const [whole, fraction = ''] = source.split('.');
  const minor = Number(whole) * 100 + Number(fraction.padEnd(2, '0'));
  if (!Number.isSafeInteger(minor) || minor > MAX_MONEY_MINOR || (positive && minor <= 0)) throw new ApiError(400, label + ': проверьте положительную сумму.');
  return minor;
}
function fromMinor(value) { return value / 100; }
function sumMinor(values) {
  const sum = values.reduce((a, b) => a + b, 0);
  if (!Number.isSafeInteger(sum) || sum < 0 || sum > MAX_MONEY_MINOR) throw new ApiError(400, 'Суммарное значение превышает допустимый размер.');
  return sum;
}
function validateLegacyDocs(docs) {
  if (!Array.isArray(docs) || docs.length !== 5 || docs.some(value => typeof value !== 'boolean')) throw new ApiError(400, 'Некорректный список документов.');
}
function defaultDocuments(docs, funding) {
  if (docs !== undefined) validateLegacyDocs(docs);
  const result = BASE_DOCUMENTS.map(([key, name]) => ({ id: key, name, required: true, received: docs ? Boolean(docs[LEGACY_DOCUMENT_IDS.indexOf(key)]) : false, receivedAt: '', note: '' }));
  if (funding === 'grant') result.push({ id: 'grant_certificate', name: 'Свидетельство о присуждении гранта', required: true, received: false, receivedAt: '', note: '' });
  if (funding === 'paid') result.push({ id: 'contract', name: 'Договор на обучение', required: true, received: false, receivedAt: '', note: '' });
  return result;
}
function documentValues(source, funding, previous = [], stampNew = true) {
  if (!Array.isArray(source) || source.length < 1 || source.length > 40) throw new ApiError(400, 'Список документов: от 1 до 40 позиций.');
  const ids = new Set();
  const result = source.map(item => {
    if (!item || Array.isArray(item) || typeof item !== 'object') throw new ApiError(400, 'Проверьте список документов.');
    fields(item, ['id', 'name', 'required', 'received', 'receivedAt', 'note']);
    const key = text(item, 'id', 80, true), name = text(item, 'name', 180, true);
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(key) || ids.has(key) || name.length < 2 || typeof item.required !== 'boolean' || typeof item.received !== 'boolean') throw new ApiError(400, 'Проверьте идентификаторы и отметки документов.');
    ids.add(key);
    let receivedAt = dateValue(item.receivedAt, 'получение документа');
    if (!item.received) receivedAt = '';
    else if (!receivedAt && stampNew && !previous?.find(old => old.id === key)?.received) receivedAt = today();
    return { id: key, name, required: item.required, received: item.received, receivedAt, note: text(item, 'note', 1000) };
  });
  for (const [key, name, applies] of [['grant_certificate', 'Свидетельство о присуждении гранта', funding === 'grant'], ['contract', 'Договор на обучение', funding === 'paid']]) {
    const existing = result.find(item => item.id === key);
    if (existing) existing.required = applies;
    else if (applies) result.push({ id: key, name, required: true, received: false, receivedAt: '', note: '' });
  }
  return result;
}
function legacyDocs(documents) { return LEGACY_DOCUMENT_IDS.map(key => Boolean(documents.find(item => item.id === key)?.received)); }
function planValues(source, funding, tuitionMinor) {
  if (!Array.isArray(source) || source.length > 60) throw new ApiError(400, 'График оплаты: не более 60 взносов.');
  if (source.length && funding !== 'paid') throw new ApiError(400, 'График взносов доступен для платного обучения.');
  const ids = new Set();
  const result = source.map(item => {
    if (!item || Array.isArray(item) || typeof item !== 'object') throw new ApiError(400, 'Проверьте график оплаты.');
    fields(item, ['id', 'label', 'dueDate', 'amount']);
    const key = text(item, 'id', 80) || id();
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(key) || ids.has(key)) throw new ApiError(400, 'Взносы должны иметь разные идентификаторы.');
    ids.add(key);
    return { id: key, label: text(item, 'label', 120, true), dueDate: dateValue(item.dueDate, 'срок взноса'), amount: fromMinor(moneyMinor(item.amount, 'Сумма взноса', true)) };
  });
  if (result.length && sumMinor(result.map(item => moneyMinor(item.amount))) !== tuitionMinor) throw new ApiError(400, 'Сумма взносов должна точно совпадать со стоимостью обучения.');
  return result;
}
function normalizeDatabase() {
  for (const key of ['payments', 'receipts', 'audit']) {
    if (database[key] === undefined) database[key] = [];
    if (!Array.isArray(database[key])) throw new Error('Раздел ' + key + ' должен быть массивом. Исходная база не изменена.');
    const keys = new Set();
    for (const item of database[key]) {
      if (!item || typeof item.id !== 'string' || !item.id || keys.has(item.id)) throw new Error('Проверьте уникальные id в разделе ' + key + '. Исходная база не изменена.');
      keys.add(item.id);
    }
  }
  for (const item of database.applicants) {
    if (item.docs !== undefined) validateLegacyDocs(item.docs);
    if (item.funding === undefined) item.funding = 'undecided';
    if (!['undecided', 'grant', 'paid'].includes(item.funding)) throw new Error('Проверьте funding у абитуриента ' + item.id);
    const tuitionMinor = moneyMinor(item.tuitionTotal ?? 0, 'Стоимость обучения');
    item.tuitionTotal = fromMinor(tuitionMinor);
    if (item.funding !== 'paid' && tuitionMinor !== 0) throw new Error('Ненулевая стоимость указывается только для платной основы: ' + item.id);
    item.documents = documentValues(item.documents ?? defaultDocuments(item.docs, item.funding), item.funding, item.documents, false);
    item.docs = legacyDocs(item.documents);
    item.installmentPlan = planValues(item.installmentPlan ?? [], item.funding, tuitionMinor);
    for (const key of INTAKE_TEXT_FIELDS) { if (item[key] === undefined) item[key] = ''; else text(item, key, key === 'priorEducation' || key === 'admissionBasis' ? 500 : 120); }
    for (const key of INTAKE_DATE_FIELDS) item[key] = dateValue(item[key], key);
    if (item.archived === undefined) item.archived = false;
    if (typeof item.archived !== 'boolean') throw new Error('Проверьте archived у абитуриента ' + item.id);
  }
  for (const payment of database.payments) {
    if (!database.applicants.some(item => item.id === payment.applicantId)) throw new Error('Платёж ссылается на отсутствующую карточку: ' + payment.id);
    const minor = moneyMinor(payment.amount, 'Сумма платежа', true);
    if (payment.amountMinor !== undefined && payment.amountMinor !== minor) throw new Error('Сумма платежа не совпадает с amountMinor: ' + payment.id);
    payment.amountMinor = minor;
    if (payment.voided === undefined) payment.voided = false;
    if (typeof payment.voided !== 'boolean') throw new Error('Проверьте отметку отмены платежа: ' + payment.id);
    if (payment.receiptId === undefined) payment.receiptId = '';
  }
}
function audit(actor, action, applicantId, changes = [], extra = {}) {
  const entry = { id: id(), at: now(), actorId: actor?.id || '', actorName: actor?.name || 'Абитуриент без входа', action, applicantId: applicantId || '', changes, ...extra };
  database.audit.push(entry);
  return entry;
}
function changesBetween(before, after, keys) { return keys.filter(key => JSON.stringify(before?.[key]) !== JSON.stringify(after[key])); }
function receiptRoot(create = false) {
  if (create) fs.mkdirSync(RECEIPTS_PATH, { recursive: true, mode: 0o700 });
  let real;
  try { real = fs.realpathSync(RECEIPTS_PATH); } catch { throw new ApiError(404, 'Квитанция не найдена.'); }
  const publicRoot = fs.realpathSync(PUBLIC);
  if (real === publicRoot || real.startsWith(publicRoot + path.sep)) throw new Error('Папка квитанций должна находиться вне public.');
  return real;
}
function receiptFile(metadata) {
  if (!metadata || !/^[a-f0-9-]{36}\.(pdf|png|jpg)$/.test(metadata.storedName || '')) throw new ApiError(404, 'Квитанция не найдена.');
  const root = receiptRoot();
  const resolved = fs.realpathSync(path.join(root, metadata.storedName));
  if (!resolved.startsWith(root + path.sep) || !fs.statSync(resolved).isFile()) throw new ApiError(404, 'Квитанция не найдена.');
  return resolved;
}
function receiptPublic(metadata) {
  if (!metadata) return null;
  let available = true; try { receiptFile(metadata); } catch { available = false; }
  return { id: metadata.id, filename: metadata.filename, mimeType: metadata.mimeType, size: metadata.size, createdAt: metadata.createdAt, createdByName: metadata.createdByName, available, url: '/api/admin/receipts/' + metadata.id };
}
function paymentPublic(payment) {
  const result = { ...payment };
  const receipt = database.receipts.find(item => item.id === payment.receiptId && item.paymentId === payment.id);
  result.receipt = receiptPublic(receipt);
  result.receiptMissing = !result.receipt?.available;
  return result;
}
function financialSummary(applicant, payments) {
  const total = moneyMinor(applicant.tuitionTotal ?? 0);
  const active = payments.filter(item => !item.voided);
  const paid = sumMinor(active.map(item => moneyMinor(item.amount, 'Сумма платежа', true)));
  const allocations = applicant.installmentPlan.map((item, index) => ({ ...item, index, minor: moneyMinor(item.amount), paidMinor: 0 }));
  let pool = 0;
  for (const payment of active) {
    const target = allocations.find(item => item.id === payment.installmentId);
    const minor = moneyMinor(payment.amount);
    if (target) { const applied = Math.min(minor, target.minor - target.paidMinor); target.paidMinor += applied; pool += minor - applied; }
    else pool += minor;
  }
  const chronological = [...allocations].sort((a, b) => (a.dueDate || '9999').localeCompare(b.dueDate || '9999') || a.index - b.index);
  for (const item of chronological) { const applied = Math.min(pool, item.minor - item.paidMinor); item.paidMinor += applied; pool -= applied; }
  const day = today();
  const next = chronological.find(item => item.paidMinor < item.minor);
  const overdue = sumMinor(allocations.filter(item => item.dueDate && item.dueDate < day).map(item => item.minor - item.paidMinor));
  return {
    tuitionTotal: fromMinor(total), paid: fromMinor(paid), balance: fromMinor(Math.max(0, total - paid)),
    percent: total ? Math.min(100, Math.round(paid / total * 10000) / 100) : 0,
    overpayment: fromMinor(Math.max(0, paid - total)), nextDueDate: next?.dueDate || '', nextDueAmount: fromMinor(next ? next.minor - next.paidMinor : 0),
    overdueAmount: fromMinor(overdue), missingReceiptCount: active.filter(item => paymentPublic(item).receiptMissing).length,
    installments: allocations.map(item => ({ id: item.id, label: item.label, dueDate: item.dueDate, amount: item.amount, paid: fromMinor(item.paidMinor), balance: fromMinor(item.minor - item.paidMinor), status: item.paidMinor >= item.minor ? 'paid' : item.dueDate && item.dueDate < day ? 'overdue' : 'pending' }))
  };
}
function adminApplicant(applicant) {
  const payments = database.payments.filter(item => item.applicantId === applicant.id);
  return { ...applicant, payments: recent(payments).map(paymentPublic), financialSummary: financialSummary(applicant, payments),
    documentsMissing: applicant.documents.filter(item => item.required && !item.received).map(item => item.name),
    audit: database.audit.filter(item => item.applicantId === applicant.id).sort((a, b) => b.at.localeCompare(a.at)) };
}
function attachmentHeader(name) {
  const ascii = name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 160) || 'receipt';
  return 'attachment; filename="' + ascii + '"; filename*=UTF-8\'\'' + encodeURIComponent(name).replace(/[!'()*]/g, char => '%' + char.charCodeAt(0).toString(16).toUpperCase());
}
async function paymentApi(req, res, route, actor) {
  const method = req.method;
  const add = route.match(/^\/api\/admin\/applicants\/([a-f0-9-]{36})\/payments$/);
  if (add && method === 'POST') {
    const body = await readJson(req); fields(body, ['amount', 'paidAt', 'method', 'reference', 'note', 'installmentId']);
    const applicant = database.applicants.find(item => item.id === add[1]); if (!applicant) throw new ApiError(404, 'Карточка не найдена.');
    if (applicant.funding !== 'paid') throw new ApiError(400, 'Платёж можно добавить только для платного обучения.');
    const amountMinor = moneyMinor(body.amount, 'Сумма платежа', true);
    const paidAt = dateValue(body.paidAt, 'дата оплаты', true); if (paidAt > today()) throw new ApiError(400, 'Будущий платёж укажите в графике, а не в журнале поступивших оплат.');
    const paymentMethod = text(body, 'method', 30, true); if (!['transfer', 'cash', 'card', 'other'].includes(paymentMethod)) throw new ApiError(400, 'Выберите способ оплаты.');
    const installmentId = text(body, 'installmentId', 80);
    if (installmentId && !applicant.installmentPlan.some(item => item.id === installmentId)) throw new ApiError(400, 'Указанный взнос отсутствует в графике.');
    sumMinor([...database.payments.filter(item => item.applicantId === applicant.id && !item.voided).map(item => moneyMinor(item.amount)), amountMinor]);
    const payment = { id: id(), applicantId: applicant.id, amount: fromMinor(amountMinor), amountMinor, paidAt, method: paymentMethod, reference: text(body, 'reference', 180), note: text(body, 'note', 2000), installmentId, createdAt: now(), createdBy: actor.id, createdByName: actor.name, voided: false, voidReason: '', voidedAt: '', voidedBy: '', voidedByName: '', receiptId: '' };
    mutateDatabase(() => { database.payments.push(payment); audit(actor, 'payment.create', applicant.id, ['payments'], { paymentId: payment.id, amount: payment.amount }); });
    json(res, 201, { payment: paymentPublic(payment), applicant: adminApplicant(applicant) }); return true;
  }
  const edit = route.match(/^\/api\/admin\/payments\/([a-f0-9-]{36})$/);
  if (edit && method === 'PATCH') {
    const body = await readJson(req); fields(body, ['voided', 'voidReason']);
    if (body.voided !== true) throw new ApiError(400, 'Платёж можно только отменить с указанием причины.');
    const reason = text(body, 'voidReason', 1000, true); if (reason.length < 3) throw new ApiError(400, 'Укажите причину отмены.');
    const index = database.payments.findIndex(item => item.id === edit[1]); if (index < 0) throw new ApiError(404, 'Платёж не найден.');
    const previous = database.payments[index]; if (previous.voided) throw new ApiError(409, 'Этот платёж уже отменён.');
    const applicant = database.applicants.find(item => item.id === previous.applicantId);
    const payment = { ...previous, voided: true, voidReason: reason, voidedAt: now(), voidedBy: actor.id, voidedByName: actor.name };
    mutateDatabase(() => { database.payments[index] = payment; audit(actor, 'payment.void', applicant.id, ['payments'], { paymentId: payment.id, voidReason: reason }); });
    json(res, 200, { payment: paymentPublic(payment), applicant: adminApplicant(applicant) }); return true;
  }
  const upload = route.match(/^\/api\/admin\/payments\/([a-f0-9-]{36})\/receipt$/);
  if (upload && method === 'POST') {
    rate(req, 'receipt-upload', 40);
    const body = await readJson(req, RECEIPT_BODY_LIMIT); fields(body, ['filename', 'mimeType', 'contentBase64']);
    const payment = database.payments.find(item => item.id === upload[1]); if (!payment) throw new ApiError(404, 'Платёж не найден.');
    if (payment.voided) throw new ApiError(409, 'Для отменённого платежа новая квитанция не добавляется.');
    const oldReceipt = database.receipts.find(item => item.id === payment.receiptId);
    if (oldReceipt && receiptPublic(oldReceipt).available) throw new ApiError(409, 'Квитанция уже приложена. Исходный файл сохраняется.');
    const filename = text(body, 'filename', 180, true), mimeType = text(body, 'mimeType', 80, true);
    if (/[\/\\\u0000-\u001f\u007f]/.test(filename) || filename === '.' || filename === '..' || filename.startsWith('.')) throw new ApiError(400, 'Некорректное имя файла.');
    const extension = path.extname(filename).toLowerCase();
    const allowed = { 'application/pdf': ['.pdf', 'pdf'], 'image/png': ['.png', 'png'], 'image/jpeg': ['.jpg,.jpeg', 'jpg'] };
    const rule = allowed[mimeType]; if (!rule || !rule[0].split(',').includes(extension)) throw new ApiError(400, 'Допускаются только PDF, JPEG и PNG с соответствующим расширением.');
    const encoded = text(body, 'contentBase64', RECEIPT_BODY_LIMIT, true, false);
    if (encoded.length > Math.ceil(RECEIPT_LIMIT / 3) * 4) throw new ApiError(413, 'Размер квитанции: не более 5 МБ.');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) throw new ApiError(400, 'Некорректное содержимое файла.');
    const bytes = Buffer.from(encoded, 'base64');
    if (!bytes.length || bytes.length > RECEIPT_LIMIT) throw new ApiError(413, 'Размер квитанции: не более 5 МБ.');
    if (bytes.toString('base64') !== encoded) throw new ApiError(400, 'Некорректная кодировка файла.');
    const signature = mimeType === 'application/pdf' ? bytes.subarray(0, 5).equals(Buffer.from('%PDF-')) : mimeType === 'image/png' ? bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])) : bytes.length >= 3 && bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255;
    if (!signature) throw new ApiError(400, 'Содержимое файла не соответствует выбранному формату.');
    const receiptId = id(), storedName = receiptId + '.' + rule[1];
    const destination = path.join(receiptRoot(true), storedName);
    let fd;
    try { fd = fs.openSync(destination, 'wx', 0o600); fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); }
    catch (error) {
      if (fd !== undefined) { fs.closeSync(fd); fd = undefined; try { fs.unlinkSync(destination); } catch {} }
      throw error;
    } finally { if (fd !== undefined) fs.closeSync(fd); }
    const receipt = { id: receiptId, paymentId: payment.id, applicantId: payment.applicantId, filename, mimeType, size: bytes.length, storedName, createdAt: now(), createdBy: actor.id, createdByName: actor.name };
    try {
      mutateDatabase(() => {
        database.receipts.push(receipt); payment.receiptId = receipt.id;
        if (oldReceipt) oldReceipt.supersededBy = receipt.id;
        audit(actor, oldReceipt ? 'receipt.restore' : 'receipt.add', payment.applicantId, ['receipts'], { paymentId: payment.id, receiptId: receipt.id });
      });
    } catch (error) { try { fs.unlinkSync(destination); } catch {} throw error; }
    const applicant = database.applicants.find(item => item.id === payment.applicantId);
    json(res, 201, { receipt: receiptPublic(receipt), payment: paymentPublic(payment), applicant: adminApplicant(applicant) }); return true;
  }
  const download = route.match(/^\/api\/admin\/receipts\/([a-f0-9-]{36})$/);
  if (download && method === 'GET') {
    const receipt = database.receipts.find(item => item.id === download[1]); if (!receipt) throw new ApiError(404, 'Квитанция не найдена.');
    let file; try { file = receiptFile(receipt); } catch { throw new ApiError(404, 'Квитанция не найдена.'); }
    res.setHeader('Content-Disposition', attachmentHeader(receipt.filename));
    res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'");
    res.setHeader('Content-Length', fs.statSync(file).size);
    send(res, 200, receipt.mimeType, fs.readFileSync(file)); return true;
  }
  return false;
}

function taskValues(body) {
  const title = text(body, 'title', 200, true); if (title.length < 2) throw new ApiError(400, 'Укажите название задачи.');
  const kind = text(body, 'kind', 20) || 'task'; if (!['task', 'meeting'].includes(kind)) throw new ApiError(400, 'Некорректный тип записи.');
  const dueAt = text(body, 'dueAt', 40); if (dueAt && !Number.isFinite(Date.parse(dueAt))) throw new ApiError(400, 'Некорректная дата.');
  const done = body.done === undefined ? false : body.done; if (typeof done !== 'boolean') throw new ApiError(400, 'Некорректная отметка выполнения.');
  return { title, kind, dueAt, done };
}
function recent(records) { return [...records].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))); }
function routeId(route, prefix) { const value = route.slice(prefix.length); if (!/^[a-f0-9-]{36}$/.test(value)) throw new ApiError(404, 'Запись не найдена.'); return value; }
function csvCell(value) { let result = value === null || value === undefined ? '' : String(value); if (/^[\s]*[=+@-]/.test(result)) result = "'" + result; return '"' + result.replace(/"/g, '""') + '"'; }
function json(res, status, body) { send(res, status, 'application/json; charset=utf-8', JSON.stringify(body)); }
function send(res, status, type, body) { res.statusCode = status; res.setHeader('Content-Type', type); res.end(body); }

async function api(req, res, route) {
  const method = req.method;
  if (['POST', 'PATCH', 'DELETE'].includes(method)) sameOrigin(req);
  if (route === '/api/programs' && method === 'GET') return json(res, 200, { programs: database.programs });
  if (route === '/api/auth/me' && method === 'GET') { const user = currentUser(req); return json(res, 200, { user: user ? safeUser(user) : null }); }
  if (route === '/api/auth/register' && method === 'POST') {
    rate(req, 'register', 10);
    const body = await readJson(req); fields(body, ['login', 'password', 'name']);
    const login = text(body, 'login', 80, true).toLowerCase(); validateLogin(login);
    const name = text(body, 'name', 120, true); if (name.length < 2) throw new ApiError(400, 'Укажите имя.');
    const password = text(body, 'password', 128, true, false); validatePassword(password);
    const user = await makeUser(login, name, password, 'student');
    // Повторная проверка после асинхронного хеширования исключает гонку одинаковых логинов.
    if (database.users.some(item => item.login.toLowerCase() === login)) throw new ApiError(409, 'Этот логин уже занят.');
    mutateDatabase(() => database.users.push(user)); newSession(req, res, user);
    return json(res, 201, { user: safeUser(user) });
  }
  if (route === '/api/auth/login' && method === 'POST') {
    rate(req, 'login', 20);
    const body = await readJson(req); fields(body, ['login', 'password']);
    const login = text(body, 'login', 80, true).toLowerCase();
    const password = text(body, 'password', 128, true, false);
    const user = database.users.find(item => item.login.toLowerCase() === login);
    if (!(await passwordMatches(password, user))) throw new ApiError(401, 'Неверный логин или пароль.');
    newSession(req, res, user); return json(res, 200, { user: safeUser(user) });
  }
  if (route === '/api/auth/logout' && method === 'POST') {
    fields(await readJson(req), []);
    const token = sessionToken(req); if (token) mutateDatabase(() => { database.sessions = database.sessions.filter(item => item.id !== sha(token)); });
    res.setHeader('Set-Cookie', sessionCookie('', 0)); return json(res, 200, { ok: true });
  }
  if (route === '/api/inquiries' && method === 'POST') {
    rate(req, 'inquiry', 10);
    const body = await readJson(req); fields(body, ['name', 'phone', 'email', 'program', 'programId', 'message', 'consent']);
    if (body.consent !== true) throw new ApiError(400, 'Подтвердите согласие на обработку данных обращения.');
    const values = applicantValues(body, false); if (!values.phone && !values.email) throw new ApiError(400, 'Укажите телефон или электронную почту.');
    const user = currentUser(req), createdAt = now();
    const applicant = { id: id(), userId: user ? user.id : '', ...values, consentAt: createdAt, createdAt, updatedAt: createdAt };
    mutateDatabase(() => { database.applicants.push(applicant); audit(user, 'applicant.create', applicant.id, ['name', 'program', 'message']); }); return json(res, 201, { ok: true, reference: applicant.id });
  }
  if (route === '/api/my/applications' && method === 'GET') {
    const user = requireUser(req);
    const applications = recent(database.applicants.filter(item => item.userId === user.id)).map(item => {
      const out = {}; for (const key of ['id', 'name', 'phone', 'email', 'program', 'level', 'message', 'status', 'docs', 'createdAt', 'updatedAt']) out[key] = item[key]; return out;
    });
    return json(res, 200, { applications });
  }
  if (route.startsWith('/api/admin/')) {
    const actor = requireAdmin(req); // Проверка обязательна для каждого административного маршрута, включая CSV и квитанции.
    if (await paymentApi(req, res, route, actor)) return;
    if (route === '/api/admin/audit' && method === 'GET') return json(res, 200, { audit: [...database.audit].sort((a, b) => b.at.localeCompare(a.at)) });
    const auditRoute = route.match(/^\/api\/admin\/applicants\/([a-f0-9-]{36})\/audit$/);
    if (auditRoute && method === 'GET') { const applicant = database.applicants.find(item => item.id === auditRoute[1]); if (!applicant) throw new ApiError(404, 'Карточка не найдена.'); return json(res, 200, { audit: adminApplicant(applicant).audit }); }
    if (route === '/api/admin/applicants') {
      if (method === 'GET') return json(res, 200, { applicants: recent(database.applicants).map(adminApplicant) });
      if (method === 'POST') {
        const body = await readJson(req); fields(body, APPLICANT_FIELDS);
        const createdAt = now(), applicant = { id: id(), userId: '', ...applicantValues(body, true), consentAt: '', createdAt, updatedAt: createdAt };
        mutateDatabase(() => { database.applicants.push(applicant); audit(actor, 'applicant.create', applicant.id, APPLICANT_FIELDS); }); return json(res, 201, { applicant: adminApplicant(applicant) });
      }
    }
    if (route.startsWith('/api/admin/applicants/')) {
      const recordId = routeId(route, '/api/admin/applicants/');
      if (method === 'PATCH') {
        const body = await readJson(req); fields(body, APPLICANT_FIELDS); if (!Object.keys(body).length) throw new ApiError(400, 'Нет изменений.');
        const index = database.applicants.findIndex(item => item.id === recordId); if (index < 0) throw new ApiError(404, 'Обращение не найдено.');
        const previous = database.applicants[index];
        const values = applicantValues({ ...previous, ...body }, true, previous, body);
        if (values.funding !== 'paid' && database.payments.some(item => item.applicantId === previous.id && !item.voided)) throw new ApiError(409, 'У карточки есть действующие платежи. Сначала исправьте ошибочные записи через отмену с указанием причины.');
        const applicant = { ...previous, ...values, updatedAt: now() };
        const changes = changesBetween(previous, applicant, APPLICANT_FIELDS);
        mutateDatabase(() => {
          database.applicants[index] = applicant;
          const otherChanges = changes.filter(key => key !== 'docs' && key !== 'documents');
          if (otherChanges.length) audit(actor, 'applicant.update', applicant.id, otherChanges);
          if (changes.includes('documents')) audit(actor, 'documents.update', applicant.id, ['documents']);
        }); return json(res, 200, { applicant: adminApplicant(applicant) });
      }
      if (method === 'DELETE') {
        fields(await readJson(req), []); const index = database.applicants.findIndex(item => item.id === recordId); if (index < 0) throw new ApiError(404, 'Обращение не найдено.');
        if (database.payments.some(item => item.applicantId === recordId)) throw new ApiError(409, 'Карточку с финансовой историей удалять нельзя. Используйте отметку архива.');
        mutateDatabase(() => { database.applicants.splice(index, 1); audit(actor, 'applicant.delete', recordId, []); }); return json(res, 200, { ok: true });
      }
    }
    if (route === '/api/admin/tasks') {
      if (method === 'GET') return json(res, 200, { tasks: recent(database.tasks) });
      if (method === 'POST') {
        const body = await readJson(req); fields(body, TASK_FIELDS);
        const task = { id: id(), ...taskValues(body), createdAt: now() }; mutateDatabase(() => { database.tasks.push(task); audit(actor, 'task.create', '', TASK_FIELDS, { taskId: task.id }); }); return json(res, 201, { task });
      }
    }
    if (route.startsWith('/api/admin/tasks/')) {
      const recordId = routeId(route, '/api/admin/tasks/');
      if (method === 'PATCH') {
        const body = await readJson(req); fields(body, TASK_FIELDS); if (!Object.keys(body).length) throw new ApiError(400, 'Нет изменений.');
        const index = database.tasks.findIndex(item => item.id === recordId); if (index < 0) throw new ApiError(404, 'Запись не найдена.');
        const task = { ...database.tasks[index], ...taskValues({ ...database.tasks[index], ...body }) };
        mutateDatabase(() => { database.tasks[index] = task; audit(actor, 'task.update', '', Object.keys(body), { taskId: task.id }); }); return json(res, 200, { task });
      }
      if (method === 'DELETE') {
        fields(await readJson(req), []); const index = database.tasks.findIndex(item => item.id === recordId); if (index < 0) throw new ApiError(404, 'Запись не найдена.');
        mutateDatabase(() => { database.tasks.splice(index, 1); audit(actor, 'task.delete', '', [], { taskId: recordId }); }); return json(res, 200, { ok: true });
      }
    }
    if (route === '/api/admin/export' && method === 'GET') {
      let csv = '\uFEFFФИО;Программа;Уровень;Статус;Баллы;Документы;Телефон;Email;Создано;Основа;Стоимость;Оплачено;Остаток;Не хватает документов\r\n';
      const fundingLabels = { undecided: 'Не определена', grant: 'Грант', paid: 'Платное обучение' };
      for (const item of recent(database.applicants).map(adminApplicant)) csv += [item.name, item.program, item.level, STATUS[item.status] || item.status, item.score, item.documents.filter(doc => doc.required && doc.received).length + '/' + item.documents.filter(doc => doc.required).length, item.phone, item.email, item.createdAt, fundingLabels[item.funding], item.financialSummary.tuitionTotal, item.financialSummary.paid, item.financialSummary.balance, item.documentsMissing.join(', ')].map(csvCell).join(';') + '\r\n';
      res.setHeader('Content-Disposition', 'attachment; filename=ZhezU_applicants.csv'); return send(res, 200, 'text/csv; charset=utf-8', csv);
    }
    throw new ApiError(405, 'Метод или раздел не поддерживается.');
  }
  throw new ApiError(404, 'Раздел не найден.');
}

function staticFile(req, res, route) {
  if (!['GET', 'HEAD'].includes(req.method)) throw new ApiError(405, 'Метод не поддерживается.');
  if (route.includes('\0') || route.includes('\\') || route.split('/').some(item => item === '.' || item === '..')) throw new ApiError(404, 'Файл не найден.');
  let target = route === '/' ? '/index.html' : route;
  if (/^\/admin$/i.test(target)) target = '/admin.html';
  if (/^\/account$/i.test(target)) target = '/account.html';
  const resolved = path.resolve(PUBLIC, '.' + target);
  if (!resolved.startsWith(PUBLIC + path.sep)) throw new ApiError(404, 'Файл не найден.');
  let file;
  try { file = fs.realpathSync(resolved); if (!fs.statSync(file).isFile() || !file.startsWith(fs.realpathSync(PUBLIC) + path.sep)) throw new Error(); }
  catch { throw new ApiError(404, 'Файл не найден.'); }
  if (path.basename(file).toLowerCase() === 'admin.html') {
    res.setHeader('Cache-Control', 'private, no-store');
    const user = currentUser(req);
    if (!user) { res.writeHead(303, { Location: '/login.html?next=%2Fadmin.html' }); return res.end(); }
    if (user.role !== 'admin') return send(res, 403, 'text/html; charset=utf-8', '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Доступ ограничен</title><body><h1>Доступ разрешён только администрации</h1><a href="/">На главную</a></body></html>');
  }
  if (path.basename(file).toLowerCase() === 'account.html') {
    res.setHeader('Cache-Control', 'private, no-store');
    if (!currentUser(req)) { res.writeHead(303, { Location: '/login.html?next=%2Faccount.html' }); return res.end(); }
  }
  const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.png': 'image/png', '.webp': 'image/webp', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
  const type = types[path.extname(file).toLowerCase()]; if (!type) throw new ApiError(404, 'Файл не найден.');
  res.setHeader('Content-Type', type);
  if (req.method === 'HEAD') { res.statusCode = 200; return res.end(); }
  res.end(fs.readFileSync(file));
}
async function handle(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  try {
    let route;
    try { route = decodeURIComponent(String(req.url || '/').split('?')[0]); } catch { throw new ApiError(400, 'Некорректный адрес.'); }
    if (!route.startsWith('/')) throw new ApiError(400, 'Некорректный адрес.');
    if (route.startsWith('/api/')) { res.setHeader('Cache-Control', 'private, no-store'); res.setHeader('Vary', 'Cookie'); await api(req, res, route); }
    else staticFile(req, res, route);
  } catch (error) {
    req.resume();
    if (!res.headersSent) json(res, error instanceof ApiError ? error.status : 500, { error: error instanceof ApiError ? error.message : 'Не удалось выполнить запрос. Повторите попытку позже.' });
    else res.end();
    if (!(error instanceof ApiError)) console.error('Ошибка обработки запроса: ' + error.name);
  }
}

// Первый сотрудник создаётся только здесь, из командной строки. Общего пароля нет.
async function promptLine(question, hidden = false) {
  if (hidden && !process.stdin.isTTY) throw new Error('Для скрытого ввода откройте терминал. Для автоматизации используйте --password-stdin.');
  const terminal = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: Boolean(process.stdin.isTTY) });
  if (hidden) {
    terminal._writeToOutput = function () {};
    process.stdout.write(question);
  }
  try { return await new Promise(resolve => terminal.question(hidden ? '' : question, resolve)); }
  finally { terminal.close(); if (hidden) process.stdout.write('\n'); }
}
async function setupAdmin() {
  let login = String(OPTIONS.login || '').trim().toLowerCase();
  if (!login) { if (OPTIONS['password-stdin']) throw new Error('При --password-stdin укажите --login.'); login = (await promptLine('Логин администратора: ')).trim().toLowerCase(); }
  validateLogin(login);
  const name = String(OPTIONS.name || 'Администратор ЖезУ').trim();
  if (name.length < 2 || name.length > 120) throw new Error('Имя: 2–120 символов.');
  if (database.users.some(item => item.login.toLowerCase() === login)) throw new Error('Этот логин уже существует. Выберите другой.');
  let password;
  if (OPTIONS['password-stdin']) {
    const content = fs.readFileSync(0, 'utf8'); password = content.split(/\r?\n/, 1)[0];
  } else {
    password = await promptLine('Пароль администратора (минимум 12 символов): ', true);
    const repeat = await promptLine('Повторите пароль: ', true); if (password !== repeat) throw new Error('Пароли не совпадают.');
  }
  validatePassword(password);
  const user = await makeUser(login, name, password, 'admin');
  mutateDatabase(() => database.users.push(user));
  console.log('Администратор создан: ' + login);
}
async function main() {
  acquireLock(); process.on('exit', releaseLock);
  loadDatabase();
  if (OPTIONS['setup-admin']) { try { await setupAdmin(); } finally { releaseLock(); } return; }
  server = http.createServer((req, res) => { void handle(req, res); });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000; server.maxHeadersCount = 64;
  server.on('error', error => { console.error(error.code === 'EADDRINUSE' ? 'Порт занят. Закройте другой сервер или укажите --port.' : 'Не удалось запустить сервер: ' + error.message); releaseLock(); process.exitCode = 1; });
  server.listen(port, OPTIONS.host || '127.0.0.1', () => { port = server.address().port; console.log('ЖезУ: http://' + (OPTIONS.host || '127.0.0.1') + ':' + port + '/'); console.log('База: ' + DB_PATH); if (OPTIONS.open && process.platform === 'win32') { const child = require('node:child_process').spawn('cmd.exe', ['/c', 'start', '', 'http://127.0.0.1:' + port + '/'], { detached: true, stdio: 'ignore', windowsHide: true }); child.on('error', () => {}); child.unref(); } });
  const shutdown = () => { server.close(() => { releaseLock(); process.exit(0); }); setTimeout(() => { releaseLock(); process.exit(0); }, 2000).unref(); };
  process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
}
main().catch(error => { console.error(error.message); releaseLock(); process.exitCode = 1; });
