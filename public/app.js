const usernameInput = document.getElementById('username');
const registerBtn = document.getElementById('registerBtn');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const logEl = document.getElementById('log');
const supportEl = document.getElementById('support');
const sessionEl = document.getElementById('session');

function log(message, data) {
  const line =
    data === undefined ? `[${new Date().toLocaleTimeString()}] ${message}` : `[${new Date().toLocaleTimeString()}] ${message}\n${JSON.stringify(data, null, 2)}`;
  logEl.textContent = `${line}\n\n${logEl.textContent}`.slice(0, 8000);
}

function base64UrlToUint8Array(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '==='.slice((base64.length + 3) % 4);
  const raw = atob(padded);
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    output[i] = raw.charCodeAt(i);
  }
  return output;
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function credentialToJSON(value) {
  if (value instanceof ArrayBuffer) {
    return arrayBufferToBase64Url(value);
  }

  if (ArrayBuffer.isView(value)) {
    const view = value;
    const sliced = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
    return arrayBufferToBase64Url(sliced);
  }

  if (value instanceof AuthenticatorAttestationResponse) {
    return {
      clientDataJSON: arrayBufferToBase64Url(value.clientDataJSON),
      attestationObject: arrayBufferToBase64Url(value.attestationObject),
      transports:
        typeof value.getTransports === 'function' ? value.getTransports() : [],
    };
  }

  if (value instanceof AuthenticatorAssertionResponse) {
    return {
      clientDataJSON: arrayBufferToBase64Url(value.clientDataJSON),
      authenticatorData: arrayBufferToBase64Url(value.authenticatorData),
      signature: arrayBufferToBase64Url(value.signature),
      userHandle: value.userHandle
        ? arrayBufferToBase64Url(value.userHandle)
        : null,
    };
  }

  if (value instanceof PublicKeyCredential) {
    const json = {
      id: value.id,
      rawId: arrayBufferToBase64Url(value.rawId),
      type: value.type,
      authenticatorAttachment: value.authenticatorAttachment,
      clientExtensionResults: value.getClientExtensionResults(),
      response: credentialToJSON(value.response),
    };
    return json;
  }

  if (Array.isArray(value)) {
    return value.map(credentialToJSON);
  }

  if (value && typeof value === 'object') {
    const converted = {};
    for (const [key, nestedValue] of Object.entries(value)) {
      converted[key] = credentialToJSON(nestedValue);
    }
    return converted;
  }

  return value;
}

function prepareRegistrationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToUint8Array(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToUint8Array(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
      ...credential,
      id: base64UrlToUint8Array(credential.id),
    })),
  };
}

function prepareAuthenticationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToUint8Array(options.challenge),
    allowCredentials: options.allowCredentials?.map((credential) => ({
      ...credential,
      id: base64UrlToUint8Array(credential.id),
    })),
  };
}

async function api(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload || {}),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

function getUsername() {
  return usernameInput.value.trim().toLowerCase();
}

async function refreshSession() {
  const response = await fetch('/api/me');
  const data = await response.json();
  sessionEl.textContent = data.loggedIn
    ? `Sessao ativa: ${data.username}`
    : 'Sessao ativa: nao autenticado';
}

async function registerPasskey() {
  const username = getUsername();
  if (!username) {
    throw new Error('Indica um utilizador antes de registar');
  }

  const options = await api('/api/register/start', { username });
  if ((options.excludeCredentials || []).length > 0) {
    throw new Error('Este utilizador já tem uma passkey registada. Não é permitido criar outra.');
  }

  const publicKey = prepareRegistrationOptions(options);
  const credential = await navigator.credentials.create({ publicKey });
  if (!credential) {
    throw new Error('Registo cancelado pelo utilizador');
  }

  const registrationResponse = credentialToJSON(credential);
  await api('/api/register/finish', { username, registrationResponse });
}

async function loginWithPasskey() {
  const username = getUsername();
  if (!username) {
    throw new Error('Indica um utilizador antes de entrar');
  }

  const options = await api('/api/login/start', { username });
  const publicKey = prepareAuthenticationOptions(options);
  const credential = await navigator.credentials.get({ publicKey });
  if (!credential) {
    throw new Error('Login cancelado pelo utilizador');
  }

  const authenticationResponse = credentialToJSON(credential);
  const result = await api('/api/login/finish', { authenticationResponse });
  usernameInput.value = result.username;
}

async function logout() {
  await api('/api/logout');
}

function setButtons(enabled) {
  registerBtn.disabled = !enabled;
  loginBtn.disabled = !enabled;
  logoutBtn.disabled = !enabled;
}

async function withAction(action, title) {
  try {
    setButtons(false);
    await action();
    log(`${title}: OK`);
  } catch (error) {
    log(`${title}: ERRO`, { message: error.message });
  } finally {
    setButtons(true);
    refreshSession();
  }
}

async function boot() {
  const supports = !!window.PublicKeyCredential;
  supportEl.textContent = supports
    ? 'WebAuthn suportado neste browser. Registo restrito a passkey movel externa (hybrid).'
    : 'Este browser nao suporta WebAuthn.';

  if (!supports) {
    setButtons(false);
    return;
  }

  registerBtn.addEventListener('click', () =>
    withAction(registerPasskey, 'Registo passkey'),
  );
  loginBtn.addEventListener('click', () =>
    withAction(loginWithPasskey, 'Login passkey'),
  );
  logoutBtn.addEventListener('click', () => withAction(logout, 'Logout'));

  await refreshSession();
}

boot().catch((error) => log('Falha ao iniciar app', { message: error.message }));
