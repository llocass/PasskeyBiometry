import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import express from 'express';
import session from 'express-session';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { recoveryWords } from './recoveryWords.js';

const app = express();
const PORT = Number(process.env.PORT || 3000);
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const DB_PATH = path.resolve(process.env.DB_PATH || path.join('data', 'passkeys.json'));
const ENFORCE_HYBRID_TRANSPORT = process.env.ENFORCE_HYBRID_TRANSPORT !== 'false';
const RECOVERY_WORD_COUNT = 10;
const RECOVERY_SESSION_TTL_MS = 10 * 60 * 1000;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

function loadStore() {
  if (!fs.existsSync(DB_PATH)) {
    const fresh = { users: [], credentials: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(fresh, null, 2), 'utf8');
    return fresh;
  }

  const raw = fs.readFileSync(DB_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  return {
    users: Array.isArray(parsed.users) ? parsed.users : [],
    credentials: Array.isArray(parsed.credentials) ? parsed.credentials : [],
  };
}

function saveStore() {
  fs.writeFileSync(DB_PATH, JSON.stringify(store, null, 2), 'utf8');
}

function normalizeRecoveryPhrase(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

function hashRecoveryPhrase(phrase, saltHex) {
  return crypto.scryptSync(normalizeRecoveryPhrase(phrase), saltHex, 64).toString('hex');
}

function generateRecoveryPhrase() {
  const words = [];
  for (let index = 0; index < RECOVERY_WORD_COUNT; index += 1) {
    words.push(recoveryWords[crypto.randomInt(0, recoveryWords.length)]);
  }
  return words.join(' ');
}

function credentialToRuntime(credential) {
  return {
    id: credential.id,
    publicKey: Buffer.from(credential.publicKeyBase64, 'base64'),
    counter: Number(credential.counter || 0),
    transports: Array.isArray(credential.transports) ? credential.transports : [],
    createdAt: credential.createdAt || null,
    lastUsedAt: credential.lastUsedAt || null,
    revokedAt: credential.revokedAt || null,
  };
}

const store = loadStore();

for (const user of store.users) {
  if (!Object.hasOwn(user, 'recoverySalt')) {
    user.recoverySalt = null;
  }
  if (!Object.hasOwn(user, 'recoveryHash')) {
    user.recoveryHash = null;
  }
  if (!Object.hasOwn(user, 'recoveryCreatedAt')) {
    user.recoveryCreatedAt = null;
  }
  if (!Object.hasOwn(user, 'recoveryLastUsedAt')) {
    user.recoveryLastUsedAt = null;
  }
}
saveStore();

function getUserByUsername(username) {
  return store.users.find((user) => user.username === username) || null;
}

function getOrCreateUser(username) {
  const existing = getUserByUsername(username);
  if (existing) {
    return existing;
  }

  const id = crypto.randomUUID();
  const user = {
    id,
    username,
    createdAt: new Date().toISOString(),
    recoverySalt: null,
    recoveryHash: null,
    recoveryCreatedAt: null,
    recoveryLastUsedAt: null,
  };
  store.users.push(user);
  saveStore();
  return user;
}

function hasRecoveryPhrase(user) {
  return Boolean(user?.recoverySalt && user?.recoveryHash);
}

function getRecoveryStatus(user) {
  return {
    configured: hasRecoveryPhrase(user),
    createdAt: user?.recoveryCreatedAt || null,
    lastUsedAt: user?.recoveryLastUsedAt || null,
    wordCount: RECOVERY_WORD_COUNT,
  };
}

function issueRecoveryPhraseForUser(user) {
  const phrase = generateRecoveryPhrase();
  const saltHex = crypto.randomBytes(16).toString('hex');
  user.recoverySalt = saltHex;
  user.recoveryHash = hashRecoveryPhrase(phrase, saltHex);
  user.recoveryCreatedAt = new Date().toISOString();
  user.recoveryLastUsedAt = null;
  saveStore();
  return {
    phrase,
    ...getRecoveryStatus(user),
  };
}

function verifyRecoveryPhraseForUser(user, phrase) {
  if (!hasRecoveryPhrase(user)) {
    return false;
  }

  const suppliedHash = hashRecoveryPhrase(phrase, user.recoverySalt);
  const expectedBuffer = Buffer.from(user.recoveryHash, 'hex');
  const suppliedBuffer = Buffer.from(suppliedHash, 'hex');
  if (expectedBuffer.length !== suppliedBuffer.length) {
    return false;
  }

  const verified = crypto.timingSafeEqual(expectedBuffer, suppliedBuffer);
  if (verified) {
    user.recoveryLastUsedAt = new Date().toISOString();
    saveStore();
  }
  return verified;
}

function hasValidRecoverySession(req) {
  return Boolean(
    req.session.recoveryUser &&
      req.session.recoveryExpiresAt &&
      Number(req.session.recoveryExpiresAt) > Date.now(),
  );
}

function clearRecoverySession(req) {
  req.session.recoveryUser = null;
  req.session.recoveryExpiresAt = null;
  req.session.recoveryChallenge = null;
}

function getCredentialsByUserID(userID) {
  return store.credentials
    .filter((credential) => credential.userID === userID && !credential.revokedAt)
    .map(credentialToRuntime);
}

function getAllCredentialsByUserID(userID) {
  return store.credentials
    .filter((credential) => credential.userID === userID)
    .map(credentialToRuntime);
}

function getUserWithCredentialsByUsername(username) {
  const user = getUserByUsername(username);
  if (!user) {
    return null;
  }

  return {
    ...user,
    credentials: getCredentialsByUserID(user.id),
  };
}

function findUserByCredentialID(credentialID) {
  const credential = store.credentials.find(
    (item) => item.id === credentialID && !item.revokedAt,
  );
  if (!credential) {
    return null;
  }

  const user = store.users.find((item) => item.id === credential.userID);
  if (!user) {
    return null;
  }

  return {
    user: {
      id: user.id,
      username: user.username,
    },
    authenticator: credentialToRuntime(credential),
  };
}

function saveCredential(userID, credential, transports) {
  const normalized = {
    id: credential.id,
    userID,
    publicKeyBase64: Buffer.from(credential.publicKey).toString('base64'),
    counter: Number(credential.counter || 0),
    transports: Array.isArray(transports) ? transports : [],
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revokedAt: null,
  };

  const index = store.credentials.findIndex((item) => item.id === credential.id);
  if (index >= 0) {
    normalized.createdAt = store.credentials[index].createdAt || normalized.createdAt;
    normalized.lastUsedAt = store.credentials[index].lastUsedAt || null;
    normalized.revokedAt = store.credentials[index].revokedAt || null;
    store.credentials[index] = normalized;
  } else {
    store.credentials.push(normalized);
  }

  saveStore();
}

function updateCredentialCounter(credentialID, newCounter) {
  const credential = store.credentials.find((item) => item.id === credentialID);
  if (!credential) {
    return;
  }

  credential.counter = Number(newCounter || 0);
  credential.lastUsedAt = new Date().toISOString();
  saveStore();
}

function listPasskeysForUser(userID) {
  return getAllCredentialsByUserID(userID)
    .sort((left, right) => {
      if (left.revokedAt && !right.revokedAt) {
        return 1;
      }
      if (!left.revokedAt && right.revokedAt) {
        return -1;
      }
      return String(right.createdAt || '').localeCompare(String(left.createdAt || ''));
    })
    .map((credential) => ({
      id: credential.id,
      shortId: credential.id.slice(0, 10),
      createdAt: credential.createdAt,
      lastUsedAt: credential.lastUsedAt,
      revokedAt: credential.revokedAt,
      transports: credential.transports,
      isActive: !credential.revokedAt,
    }));
}

function revokeCredentialForUser(userID, credentialID) {
  const credential = store.credentials.find(
    (item) => item.id === credentialID && item.userID === userID,
  );
  if (!credential) {
    return { ok: false, error: 'Passkey not found for this user', status: 404 };
  }
  if (credential.revokedAt) {
    return { ok: false, error: 'Passkey is already revoked', status: 409 };
  }

  credential.revokedAt = new Date().toISOString();
  saveStore();
  return { ok: true, credential };
}

function revokeActiveCredentialsForUser(userID) {
  const revokedAt = new Date().toISOString();
  let changed = false;
  for (const credential of store.credentials) {
    if (credential.userID === userID && !credential.revokedAt) {
      credential.revokedAt = revokedAt;
      changed = true;
    }
  }
  if (changed) {
    saveStore();
  }
}

app.use(express.json({ limit: '1mb' }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    },
  }),
);
app.use(express.static('public'));

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    rpID: RP_ID,
    origin: ORIGIN,
    users: store.users.length,
    dbPath: DB_PATH,
  });
});

app.post('/api/register/start', async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const existingUser = getUserByUsername(username);
  if (existingUser) {
    const activeCredentials = getCredentialsByUserID(existingUser.id);
    const credentialHistory = getAllCredentialsByUserID(existingUser.id);
    if (activeCredentials.length > 0) {
      return res.status(409).json({
        error: 'This user already has a registered passkey. Only one passkey is allowed.',
      });
    }
    if (credentialHistory.length > 0 || hasRecoveryPhrase(existingUser)) {
      return res.status(409).json({
        error:
          'This account already exists. Use the recovery flow to enroll a replacement passkey.',
      });
    }
  }

  const user = existingUser || getOrCreateUser(username);
  const credentials = getCredentialsByUserID(user.id);
  if (credentials.length > 0) {
    return res.status(409).json({
      error: 'This user already has a registered passkey. Only one passkey is allowed.',
    });
  }

  const options = await generateRegistrationOptions({
    rpID: RP_ID,
    rpName: 'Passkey Biometria Local',
    userID: Buffer.from(user.id, 'utf8'),
    userName: user.username,
    userDisplayName: user.username,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      residentKey: 'required',
      userVerification: 'required',
    },
    supportedAlgorithmIDs: [-7, -257],
    excludeCredentials: credentials.map((credential) => ({
      id: credential.id,
      transports: credential.transports,
    })),
  });

  req.session.currentChallenge = options.challenge;
  req.session.currentUser = user.username;

  return res.json(options);
});

app.post('/api/register/finish', async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const registrationResponse = req.body?.registrationResponse;
  const expectedChallenge = req.session.currentChallenge;

  if (!username || !registrationResponse || !expectedChallenge) {
    return res.status(400).json({ error: 'Missing registration data' });
  }
  if (req.session.currentUser !== username) {
    return res.status(400).json({ error: 'Registration session mismatch' });
  }

  const user = getUserByUsername(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  const existingCredentials = getCredentialsByUserID(user.id);
  const credentialHistory = getAllCredentialsByUserID(user.id);
  if (existingCredentials.length > 0 || credentialHistory.length > 0 || hasRecoveryPhrase(user)) {
    return res.status(409).json({
      error:
        'This account already exists. Use the recovery flow to enroll a replacement passkey.',
    });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Registration failed' });
  }

  const { verified, registrationInfo } = verification;
  if (!verified || !registrationInfo) {
    return res.status(400).json({ error: 'Registration could not be verified' });
  }
  if (registrationResponse.authenticatorAttachment === 'platform') {
    return res.status(400).json({
      error:
        'Local device passkeys are not allowed. Use a mobile device passkey via QR/Bluetooth.',
    });
  }

  const credential = registrationInfo.credential;
  const transports = Array.isArray(registrationResponse.response?.transports)
    ? registrationResponse.response.transports
    : [];
  if (ENFORCE_HYBRID_TRANSPORT && !transports.includes('hybrid')) {
    return res.status(400).json({
      error:
        'Only mobile-linked passkeys are allowed. Complete registration using the phone flow (hybrid transport).',
    });
  }
  const credentialOwner = findUserByCredentialID(credential.id);
  if (credentialOwner && credentialOwner.user.id !== user.id) {
    return res.status(409).json({ error: 'Credential already belongs to another user' });
  }

  saveCredential(user.id, credential, transports);

  req.session.currentChallenge = null;
  req.session.currentUser = null;
  req.session.loggedInUser = user.username;

  return res.json({ verified: true, username: user.username });
});

app.post('/api/login/start', async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  if (!username) {
    return res.status(400).json({ error: 'Username is required for login' });
  }

  const user = getUserWithCredentialsByUsername(username);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (user.credentials.length === 0) {
    return res.status(400).json({ error: 'User has no registered passkeys yet' });
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials: user.credentials.map((credential) => ({
      id: credential.id,
      transports: credential.transports,
    })),
  });

  req.session.currentChallenge = options.challenge;
  req.session.currentUser = user.username;

  return res.json(options);
});

app.post('/api/login/finish', async (req, res) => {
  const authenticationResponse = req.body?.authenticationResponse;
  const expectedChallenge = req.session.currentChallenge;

  if (!authenticationResponse || !expectedChallenge) {
    return res.status(400).json({ error: 'Missing authentication data' });
  }
  if (!req.session.currentUser) {
    return res.status(400).json({ error: 'Login session is missing user' });
  }

  const currentUser = getUserWithCredentialsByUsername(req.session.currentUser);
  if (!currentUser) {
    return res.status(404).json({ error: 'User not found for this session' });
  }
  const authenticator = currentUser.credentials.find(
    (credential) => credential.id === authenticationResponse.id,
  );
  if (!authenticator) {
    return res.status(404).json({ error: 'Credential not registered for this user' });
  }
  const lookup = { user: currentUser, authenticator };

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: authenticationResponse,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      credential: {
        id: lookup.authenticator.id,
        publicKey: lookup.authenticator.publicKey,
        counter: lookup.authenticator.counter,
        transports: lookup.authenticator.transports,
      },
    });
  } catch (error) {
    return res
      .status(400)
      .json({ error: error.message || 'Authentication verification failed' });
  }

  const { verified, authenticationInfo } = verification;
  if (!verified) {
    return res.status(400).json({ error: 'Authentication failed' });
  }

  updateCredentialCounter(lookup.authenticator.id, authenticationInfo.newCounter);

  req.session.currentChallenge = null;
  req.session.currentUser = null;
  req.session.loggedInUser = lookup.user.username;

  return res.json({ verified: true, username: lookup.user.username });
});

app.get('/api/me', (req, res) => {
  if (!req.session.loggedInUser) {
    return res.status(401).json({ loggedIn: false });
  }
  const user = getUserByUsername(req.session.loggedInUser);
  if (!user) {
    return res.status(404).json({ loggedIn: false });
  }
  return res.json({
    loggedIn: true,
    username: req.session.loggedInUser,
    recovery: getRecoveryStatus(user),
  });
});

app.get('/api/passkeys', (req, res) => {
  if (!req.session.loggedInUser) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const user = getUserByUsername(req.session.loggedInUser);
  if (!user) {
    return res.status(404).json({ error: 'User not found for this session' });
  }

  return res.json({
    username: user.username,
    passkeys: listPasskeysForUser(user.id),
  });
});

app.post('/api/passkeys/revoke', (req, res) => {
  if (!req.session.loggedInUser) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const credentialID = String(req.body?.credentialId || '').trim();
  if (!credentialID) {
    return res.status(400).json({ error: 'credentialId is required' });
  }

  const user = getUserByUsername(req.session.loggedInUser);
  if (!user) {
    return res.status(404).json({ error: 'User not found for this session' });
  }
  if (!hasRecoveryPhrase(user)) {
    return res.status(400).json({
      error: 'Configure a recovery phrase before revoking the current passkey.',
    });
  }

  const result = revokeCredentialForUser(user.id, credentialID);
  if (!result.ok) {
    return res.status(result.status).json({ error: result.error });
  }

  req.session.destroy(() => {
    res.json({
      ok: true,
      username: user.username,
      revokedCredentialId: credentialID,
    });
  });
});

app.get('/api/recovery/status', (req, res) => {
  if (!req.session.loggedInUser) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const user = getUserByUsername(req.session.loggedInUser);
  if (!user) {
    return res.status(404).json({ error: 'User not found for this session' });
  }

  return res.json(getRecoveryStatus(user));
});

app.post('/api/recovery/setup', (req, res) => {
  if (!req.session.loggedInUser) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const user = getUserByUsername(req.session.loggedInUser);
  if (!user) {
    return res.status(404).json({ error: 'User not found for this session' });
  }

  const rotate = Boolean(req.body?.rotate);
  if (hasRecoveryPhrase(user) && !rotate) {
    return res.json({
      generated: false,
      ...getRecoveryStatus(user),
    });
  }

  return res.json({
    generated: true,
    ...issueRecoveryPhraseForUser(user),
  });
});

app.post('/api/recovery/verify', (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const phrase = normalizeRecoveryPhrase(req.body?.phrase);
  if (!username || !phrase) {
    return res.status(400).json({ error: 'username and phrase are required' });
  }

  const user = getUserByUsername(username);
  if (!user || !verifyRecoveryPhraseForUser(user, phrase)) {
    return res.status(400).json({ error: 'Recovery phrase is invalid' });
  }

  req.session.loggedInUser = null;
  req.session.currentUser = null;
  req.session.currentChallenge = null;
  req.session.recoveryUser = user.username;
  req.session.recoveryExpiresAt = Date.now() + RECOVERY_SESSION_TTL_MS;
  req.session.recoveryChallenge = null;

  return res.json({
    ok: true,
    username: user.username,
    expiresAt: req.session.recoveryExpiresAt,
  });
});

app.post('/api/recovery/register/start', async (req, res) => {
  if (!hasValidRecoverySession(req)) {
    clearRecoverySession(req);
    return res.status(401).json({ error: 'Recovery session expired or missing' });
  }

  const user = getUserByUsername(req.session.recoveryUser);
  if (!user) {
    clearRecoverySession(req);
    return res.status(404).json({ error: 'User not found for this recovery session' });
  }

  const options = await generateRegistrationOptions({
    rpID: RP_ID,
    rpName: 'Passkey Biometria Local',
    userID: Buffer.from(user.id, 'utf8'),
    userName: user.username,
    userDisplayName: user.username,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      residentKey: 'required',
      userVerification: 'required',
    },
    supportedAlgorithmIDs: [-7, -257],
    excludeCredentials: [],
  });

  req.session.recoveryChallenge = options.challenge;
  return res.json(options);
});

app.post('/api/recovery/register/finish', async (req, res) => {
  if (!hasValidRecoverySession(req)) {
    clearRecoverySession(req);
    return res.status(401).json({ error: 'Recovery session expired or missing' });
  }

  const registrationResponse = req.body?.registrationResponse;
  const expectedChallenge = req.session.recoveryChallenge;
  if (!registrationResponse || !expectedChallenge) {
    return res.status(400).json({ error: 'Missing recovery registration data' });
  }

  const user = getUserByUsername(req.session.recoveryUser);
  if (!user) {
    clearRecoverySession(req);
    return res.status(404).json({ error: 'User not found for this recovery session' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
  } catch (error) {
    return res
      .status(400)
      .json({ error: error.message || 'Recovery registration failed' });
  }

  const { verified, registrationInfo } = verification;
  if (!verified || !registrationInfo) {
    return res.status(400).json({ error: 'Recovery registration could not be verified' });
  }
  if (registrationResponse.authenticatorAttachment === 'platform') {
    return res.status(400).json({
      error:
        'Local device passkeys are not allowed. Use a mobile device passkey via QR/Bluetooth.',
    });
  }

  const credential = registrationInfo.credential;
  const transports = Array.isArray(registrationResponse.response?.transports)
    ? registrationResponse.response.transports
    : [];
  if (ENFORCE_HYBRID_TRANSPORT && !transports.includes('hybrid')) {
    return res.status(400).json({
      error:
        'Only mobile-linked passkeys are allowed. Complete registration using the phone flow (hybrid transport).',
    });
  }

  revokeActiveCredentialsForUser(user.id);
  saveCredential(user.id, credential, transports);
  const recoverySetup = issueRecoveryPhraseForUser(user);

  clearRecoverySession(req);
  req.session.loggedInUser = user.username;

  return res.json({
    verified: true,
    username: user.username,
    recoveryPhrase: recoverySetup.phrase,
    recovery: getRecoveryStatus(user),
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.listen(PORT, () => {
  console.log(`Server running at ${ORIGIN}`);
  console.log(`Data file: ${DB_PATH}`);
});
