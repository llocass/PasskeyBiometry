const usernameInput = document.getElementById('username');
const registerBtn = document.getElementById('registerBtn');
const loginBtn = document.getElementById('loginBtn');
const authCard = document.getElementById('authCard');
const homeCard = document.getElementById('homeCard');
const homeUser = document.getElementById('homeUser');
const homeLogoutBtn = document.getElementById('homeLogoutBtn');
const passkeySummary = document.getElementById('passkeySummary');
const passkeyList = document.getElementById('passkeyList');
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

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    };
    return map[character];
  });
}

function formatDateTime(value) {
  if (!value) {
    return 'Ainda sem registo';
  }

  return new Intl.DateTimeFormat('pt-PT', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}

function renderPasskeys(passkeys) {
  if (!passkeys.length) {
    passkeySummary.textContent = 'Sem passkeys associadas a esta conta.';
    passkeyList.innerHTML =
      '<p class="passkeyEmpty">Nao existe nenhuma passkey ativa. Podes voltar a registar uma nova.</p>';
    return;
  }

  const activeCount = passkeys.filter((passkey) => passkey.isActive).length;
  const revokedCount = passkeys.length - activeCount;
  passkeySummary.textContent = `${activeCount} ativa(s), ${revokedCount} revogada(s)`;
  passkeyList.innerHTML = passkeys
    .map((passkey) => {
      const transports = passkey.transports.length
        ? passkey.transports.join(', ')
        : 'Nao reportado';

      return `
        <article class="passkeyItem">
          <div class="passkeyItemHead">
            <div>
              <p class="passkeyTitle">Passkey ${escapeHtml(passkey.shortId)}</p>
            </div>
            <span class="badge ${passkey.isActive ? 'badgeActive' : 'badgeRevoked'}">
              ${passkey.isActive ? 'Ativa' : 'Revogada'}
            </span>
          </div>
          <div class="passkeyMeta">
            <div class="passkeyMetaBlock">
              <span class="passkeyMetaLabel">Criada em</span>
              <span class="passkeyMetaValue">${escapeHtml(formatDateTime(passkey.createdAt))}</span>
            </div>
            <div class="passkeyMetaBlock">
              <span class="passkeyMetaLabel">Ultimo uso</span>
              <span class="passkeyMetaValue">${escapeHtml(formatDateTime(passkey.lastUsedAt))}</span>
            </div>
            <div class="passkeyMetaBlock">
              <span class="passkeyMetaLabel">Transportes</span>
              <span class="passkeyMetaValue">${escapeHtml(transports)}</span>
            </div>
            <div class="passkeyMetaBlock">
              <span class="passkeyMetaLabel">ID completo</span>
              <span class="passkeyMetaValue">${escapeHtml(passkey.id)}</span>
            </div>
          </div>
          ${
            passkey.isActive
              ? `<div class="actions"><button type="button" class="dangerButton" data-passkey-action="revoke" data-passkey-id="${escapeHtml(passkey.id)}">Revogar passkey</button></div>`
              : ''
          }
        </article>
      `;
    })
    .join('');
}

async function refreshPasskeys() {
  const response = await fetch('/api/passkeys');
  if (response.status === 401) {
    passkeySummary.textContent = '';
    passkeyList.innerHTML = '';
    return;
  }

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || 'Nao foi possivel carregar as passkeys');
  }

  renderPasskeys(data.passkeys || []);
}

async function refreshSession() {
  const response = await fetch('/api/me');
  const data = await response.json();
  if (data.loggedIn) {
    sessionEl.textContent = `Sessao ativa: ${data.username}`;
    homeUser.textContent = `Utilizador: ${data.username}`;
    authCard.classList.add('hidden');
    homeCard.classList.remove('hidden');
    usernameInput.value = data.username;
    await refreshPasskeys();
  } else {
    sessionEl.textContent = 'Sessao ativa: nao autenticado';
    homeUser.textContent = '';
    authCard.classList.remove('hidden');
    homeCard.classList.add('hidden');
    passkeySummary.textContent = '';
    passkeyList.innerHTML = '';
  }
}

async function registerPasskey() {
  const username = getUsername();
  if (!username) {
    throw new Error('Indica um utilizador antes de registar');
  }

  const options = await api('/api/register/start', { username });
  if ((options.excludeCredentials || []).length > 0) {
    throw new Error('Este utilizador ja tem uma passkey registada. Nao e permitido criar outra.');
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

async function revokePasskey(credentialId) {
  const confirmed = window.confirm(
    'Isto vai revogar a passkey atual e terminar a sessao. Queres continuar?',
  );
  if (!confirmed) {
    return { cancelled: true };
  }

  const result = await api('/api/passkeys/revoke', { credentialId });
  usernameInput.value = result.username;
  return { cancelled: false };
}

function setButtons(enabled) {
  registerBtn.disabled = !enabled;
  loginBtn.disabled = !enabled;
  homeLogoutBtn.disabled = !enabled;
  for (const actionButton of passkeyList.querySelectorAll('[data-passkey-action]')) {
    actionButton.disabled = !enabled;
  }
}

async function withAction(action, title) {
  try {
    setButtons(false);
    const result = await action();
    if (result?.cancelled) {
      return;
    }
    log(`${title}: OK`);
  } catch (error) {
    log(`${title}: ERRO`, { message: error.message });
  } finally {
    setButtons(true);
    await refreshSession();
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
  homeLogoutBtn.addEventListener('click', () => withAction(logout, 'Logout'));
  passkeyList.addEventListener('click', (event) => {
    const button = event.target.closest('[data-passkey-action="revoke"]');
    if (!button) {
      return;
    }

    withAction(
      () => revokePasskey(button.getAttribute('data-passkey-id')),
      'Revogar passkey',
    );
  });

  await refreshSession();
}

boot().catch((error) => log('Falha ao iniciar app', { message: error.message }));
