## Passkey + Biometria em Localhost

<img width="1896" height="908" alt="{8812C905-B650-4966-B609-CADED9B3C08A}" src="https://github.com/user-attachments/assets/71dc21cb-be39-40ca-a9b1-db403cd0a1e4" />

Prototipo de login sem password com WebAuthn (passkeys), exigindo validacao do utilizador (`userVerification: required`) num dispositivo móvel.

## O que este projeto faz

- Registo de passkey por utilizador.
- Login com passkey (utilizador obrigatorio).
- Sessao local via cookie.
- Persistencia em ficheiro JSON local.
- Apenas 1 passkey por utilizador.
- Registo restrito a autenticador externo (cross-platform), com validacao de transporte `hybrid` por defeito.
- Gestao da passkey no checkpoint: visualizacao de metadata, ultimo uso e revogacao para reenrolamento.

## Requisitos

- Node.js 20+ (recomendado).
- Browser com suporte WebAuthn (Chrome, Edge, Safari, etc.).

## Como correr

```bash
npm install
npm run start
```

Abrir:

`http://localhost:3000`

## Fluxo de teste

1. Inserir nome de utilizador.
2. Clicar em `Registar passkey` e confirmar biometria/PIN no dispositivo.
3. Clicar em `Entrar com passkey`.
4. No checkpoint autenticado, ver a passkey ativa e revoga-la se for preciso registar outra.

## Telemovel como autenticador

- Num PC, o browser pode oferecer usar outro dispositivo (normalmente via QR code/Bluetooth).
- A verificacao exata (Face ID, impressao digital, PIN) depende do SO e do autenticador.
- O servidor exige apenas que exista verificacao do utilizador.
- Nota: a WebAuthn nao permite garantir 100% "apenas telemovel"; esta app aplica a politica mais restritiva possivel (`cross-platform` + `hybrid`).

## Variaveis de ambiente opcionais

- `PORT` (default `3000`)
- `RP_ID` (default `localhost`)
- `ORIGIN` (default `http://localhost:<PORT>`)
- `SESSION_SECRET` (default gerado no arranque)
- `DB_PATH` (default `./data/passkeys.json`)
- `ENFORCE_HYBRID_TRANSPORT` (default `true`; usar `false` para desativar o bloqueio por `hybrid`)

## Estrutura

- `server.js`: API + verificacao WebAuthn.
- `public/index.html`: UI simples.
- `public/app.js`: chamadas API e WebAuthn no browser.
- `data/passkeys.json`: armazenamento local (criado automaticamente).
