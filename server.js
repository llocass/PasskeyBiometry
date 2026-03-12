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

const app = express();
const PORT = Number(process.env.PORT || 3000);
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const DB_PATH = path.resolve(process.env.DB_PATH || path.join('data', 'passkeys.json'));
const ENFORCE_HYBRID_TRANSPORT = process.env.ENFORCE_HYBRID_TRANSPORT !== 'false';

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

function credentialToRuntime(credential) {
  return {
    id: credential.id,
    publicKey: Buffer.from(credential.publicKeyBase64, 'base64'),
    counter: Number(credential.counter || 0),
    transports: Array.isArray(credential.transports) ? credential.transports : [],
  };
}

const store = loadStore();

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
  };
  store.users.push(user);
  saveStore();
  return user;
}

function getCredentialsByUserID(userID) {
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
  const credential = store.credentials.find((item) => item.id === credentialID);
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
  };

  const index = store.credentials.findIndex((item) => item.id === credential.id);
  if (index >= 0) {
    normalized.createdAt = store.credentials[index].createdAt || normalized.createdAt;
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
  saveStore();
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

  const user = getOrCreateUser(username);
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
  if (existingCredentials.length > 0) {
    return res.status(409).json({
      error: 'This user already has a registered passkey. Only one passkey is allowed.',
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
  return res.json({
    loggedIn: true,
    username: req.session.loggedInUser,
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
