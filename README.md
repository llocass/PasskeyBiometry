## Passkey + Biometria em Localhost

<img width="1896" height="908" alt="{8812C905-B650-4966-B609-CADED9B3C08A}" src="https://github.com/user-attachments/assets/71dc21cb-be39-40ca-a9b1-db403cd0a1e4" />

Protótipo de login sem password com WebAuthn (passkeys), exigindo validação do utilizador (`userVerification: required`) num dispositivo móvel.

## O que este projeto faz

- Registo de passkey por utilizador.
- Login com passkey (utilizador obrigatório).
- Sessão local via cookie.
- Persistência em ficheiro JSON local.
- Apenas 1 passkey por utilizador.
- Registo restrito a autenticador externo (cross-platform), com validação de transporte `hybrid` por defeito.
- Gestão da passkey no checkpoint: visualização de metadata, último uso e revogação para reenrolamento.
- Frase de recuperação com 10 palavras para recuperar a conta e reenrolar uma nova passkey se o dispositivo for perdido.

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
4. No checkpoint autenticado, ver a passkey ativa e revogá-la se for preciso registar outra.
5. Guardar a frase de recuperação mostrada uma única vez.

## Telemóvel como autenticador

- Num PC, o browser pode oferecer usar outro dispositivo (normalmente via QR code/Bluetooth).
- A verificação exata (Face ID, impressão digital, PIN) depende do SO e do autenticador.
- O servidor exige apenas que exista verificação do utilizador.
- Nota: a WebAuthn não permite garantir 100% "apenas telemóvel"; esta app aplica a política mais restritiva possível (`cross-platform` + `hybrid`).

## Recuperação de conta

- Depois do primeiro registo, o sistema gera uma frase de recuperação com 10 palavras e mostra-a uma única vez.
- O servidor guarda apenas `salt + hash` da frase.
- Se o dispositivo da passkey for perdido, o utilizador pode validar a frase e reenrolar uma nova passkey.
- No final da recuperação, a passkey antiga é revogada e a frase de recuperação é regenerada.

## Como funciona a frase de recuperação

1. A conta é criada normalmente com passkey e verificação biométrica.
2. Depois do registo inicial, o sistema gera uma frase de recuperação com 10 palavras aleatórias.
3. Essa frase é mostrada uma única vez ao utilizador e deve ser guardada offline.
4. No servidor, a frase não é guardada em claro: apenas `salt + hash`.
5. Se a passkey do dispositivo for perdida, o utilizador pode iniciar o fluxo `Recuperar conta`.
6. A frase validada não faz login direto. Em vez disso, abre uma sessão curta de recuperação.
7. Nessa sessão, o utilizador é obrigado a registar uma nova passkey.
8. Quando a nova passkey fica ativa, a passkey anterior é revogada e a frase de recuperação é renovada.

## Garantias deste fluxo

- O login normal continua a ser apenas com passkey.
- A frase de recuperação serve apenas para recuperar a conta, não para autenticar no dia a dia.
- A revogação da passkey ativa exige que exista uma frase de recuperação configurada, para evitar lockout acidental.
- O reenrolamento de uma nova passkey para contas existentes só é permitido pelo fluxo de recuperação.

## Variáveis de ambiente opcionais

- `PORT` (default `3000`)
- `RP_ID` (default `localhost`)
- `ORIGIN` (default `http://localhost:<PORT>`)
- `SESSION_SECRET` (default gerado no arranque)
- `DB_PATH` (default `./data/passkeys.json`)
- `ENFORCE_HYBRID_TRANSPORT` (default `true`; usar `false` para desativar o bloqueio por `hybrid`)

## Estrutura

- `server.js`: API + verificação WebAuthn.
- `public/index.html`: UI simples.
- `public/app.js`: chamadas API e WebAuthn no browser.
- `data/passkeys.json`: armazenamento local (criado automaticamente).
