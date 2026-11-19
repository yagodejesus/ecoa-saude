# Ecoa Saúde

[English](#english) | [Português](#português)

## English

A **fact-checking** and **AI-generated content detection** platform for text, links, images and videos. Users submit content and get a verdict (likely false, suspicious, unverified or likely true), with an explanation, related fact-checks and recent news on the topic.

The project is a single-file Node.js/Express server ([app.js](app.js)) that serves the web interface and a REST API for the mobile app. The interface and prompts are in Brazilian Portuguese.

### Features

- **Text and link checking**: extracts the main claim, gathers evidence and classifies the content with an LLM.
  - For links, the page is downloaded and its text is extracted with Cheerio.
  - Evidence comes from the [Google Fact Check Tools API](https://developers.google.com/fact-check/tools/api) and Google News (RSS, pt-BR).
- **AI detection in images**: heuristic analysis using several techniques (EXIF metadata, gradients, bloom/halo, contrast, lighting, artifacts, edges, banding, entropy, format, etc.), with a heatmap and a per-technique breakdown.
- **Video analysis**: extracts frames with FFmpeg, runs AI detection on each one and, if Whisper is configured, transcribes the audio for fact-checking.
- **User accounts**: sign-up, login, password recovery by e-mail, profile editing, password change and account deletion.
- **Per-user history**: stores the last 20 checks with the full result, so they can be reopened without running the analysis again.
- **Admin panel** (`/admin`): metrics, activity log, push notifications (Expo) and CSV data export.
- **Mobile API** (`/api/*`): Bearer token authentication and the same features as the web version.

### LLM

The app picks the model as follows:

1. If `OPENAI_API_KEY` is set, it uses OpenAI (default: `gpt-4o-mini`).
2. Otherwise, it uses a local [Ollama](https://ollama.com) instance (default: `gemma3` at `http://localhost:11434`).

### Requirements

- Node.js **22.x**
- FFmpeg: bundled via `ffmpeg-static`; if unavailable, the app falls back to `ffmpeg` on the PATH
- Optional: Ollama, if you are not using OpenAI
- Optional: [whisper.cpp](https://github.com/ggerganov/whisper.cpp) to transcribe video audio

### Running locally

```bash
git clone https://github.com/yagodejesus/ecoa-saude.git
cd ecoa-saude
npm install
```

Create a `.env` file in the project root (see the variables below) and start the server:

```bash
npm start
```

Open `http://localhost:3000`. The SQLite database (`verifacts.db`) is created automatically on first run.

### Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | Server port |
| `NODE_ENV` | — | Set to `production` in production (secure cookies and configuration warnings) |
| `APP_URL` | `http://localhost:PORT` | Public URL, used in password reset links |
| `SESSION_SECRET` | dev value | **Required in production.** Session secret |
| `DB_PATH` | `./verifacts.db` | SQLite database path |
| `ADMIN_EMAILS` | — | Comma-separated e-mails with access to `/admin` |
| `OPENAI_API_KEY` | — | OpenAI key. Without it, the app uses Ollama |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama address |
| `OLLAMA_MODEL` | `gemma3` | Ollama model |
| `GOOGLE_FACTCHECK_API_KEY` | — | Google Fact Check Tools API key |
| `MAX_NEWS_ITEMS` | `15` | Maximum news items fetched per check |
| `NEWS_LOOKBACK_DAYS` | `90` | News search window, in days |
| `MAX_SCRAPED_CHARS` | `5000` | Character limit extracted from a link |
| `MAX_VIDEO_FRAMES` | `6` | Maximum frames analyzed per video |
| `FRAME_INTERVAL_SECONDS` | `8` | Interval between extracted frames |
| `WHISPER_COMMAND` | — | whisper.cpp executable |
| `WHISPER_MODEL` | — | Path to the Whisper model |
| `TEMP_DIR` | `./tmp` | Folder for temporary files and uploads |
| `SMTP_HOST` / `SMTP_PORT` | — / `587` | SMTP server for password recovery e-mails |
| `SMTP_USER` / `SMTP_PASS` | — | SMTP credentials |
| `SMTP_FROM` | `SMTP_USER` | Sender address |

Without SMTP, the password reset link is printed to the server log.

Minimal `.env` example:

```env
SESSION_SECRET=replace-with-a-long-random-value
OPENAI_API_KEY=sk-...
GOOGLE_FACTCHECK_API_KEY=...
ADMIN_EMAILS=admin@example.com
```

### Deploying to Railway

1. Create a service from this repository; the start command is `npm start`.
2. Set the environment variables, at least `NODE_ENV=production`, `SESSION_SECRET` and `APP_URL`.
3. Mount a **Volume** (for example at `/data`) and set `DB_PATH=/data/verifacts.db`. Without it, the database is wiped on every deploy.
4. Use `GET /health` as the health check.

### Mobile API

Every route below, except the authentication ones, requires the `Authorization: Bearer <token>` header.

| Method | Route | Description |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Creates an account (`email`, `password`) and returns a token |
| `POST` | `/api/auth/login` | Logs in and returns a token |
| `GET` | `/api/me` | Current user data |
| `POST` | `/api/verify` | Checks a text or link (`content`) |
| `POST` | `/api/verify/image` | Checks an image (multipart, `file` field) |
| `POST` | `/api/verify/video` | Checks a video (multipart, `file` field) |
| `GET` | `/api/history` | Lists the history |
| `GET` | `/api/history/:id/result` | Full result of a history item |
| `DELETE` | `/api/history/:id` | Removes a history item |
| `DELETE` | `/api/history` | Clears the history |
| `POST` | `/api/push/register` | Registers the device's push token (Expo) |
| `GET` | `/api/account` | Account data |
| `POST` | `/api/account/profile` | Updates the profile |
| `POST` | `/api/account/password` | Changes the password |
| `POST` | `/api/account/delete` | Deletes the account |

Uploads accept images or videos only, up to 80 MB.

### Security

- Passwords hashed with bcrypt.
- Sessions stored in SQLite, with `httpOnly` cookies.
- Per-IP rate limiting on login, sign-up and password recovery.
- Password reset tokens expire after 1 hour and can only be used once.

### Limitations

AI detection in images relies on **heuristics**, not a trained model, and can be wrong in both directions. Fact-check verdicts depend on the evidence found and on the LLM used. Treat the results as an aid to verification, not as definitive proof.

### License

Distributed under the MIT License. See [LICENSE](LICENSE.txt).

---

## Português

Plataforma de **verificação de fatos** e **detecção de conteúdo gerado por IA** em textos, links, imagens e vídeos. O usuário envia um conteúdo e recebe um veredito (provavelmente falso, suspeito, não verificado ou provavelmente verdadeiro), com justificativa, checagens de fatos relacionadas e notícias recentes sobre o assunto.

O projeto é um servidor Node.js/Express de arquivo único ([app.js](app.js)) que serve a interface web e uma API REST para o app mobile.

### Funcionalidades

- **Checagem de textos e links**: extrai a alegação principal, busca evidências e classifica o conteúdo com um LLM.
  - Para links, a página é baixada e o texto é extraído com Cheerio.
  - Evidências vêm da [Google Fact Check Tools API](https://developers.google.com/fact-check/tools/api) e do Google News (RSS, pt-BR).
- **Detecção de IA em imagens**: análise heurística com várias técnicas (metadados EXIF, gradientes, bloom/halo, contraste, iluminação, artefatos, bordas, banding, entropia, formato etc.), com mapa de calor e detalhamento de cada técnica.
- **Análise de vídeos**: extrai frames com FFmpeg, roda a detecção de IA em cada um e, se o Whisper estiver configurado, transcreve o áudio para a checagem.
- **Contas de usuário**: cadastro, login, recuperação de senha por e-mail, edição de perfil, troca de senha e exclusão de conta.
- **Histórico por usuário**: guarda as últimas 20 verificações com o resultado completo, para reabrir sem refazer a análise.
- **Painel administrativo** (`/admin`): métricas, log de atividades, envio de notificações push (Expo) e exportação de dados em CSV.
- **API mobile** (`/api/*`): autenticação por token Bearer e os mesmos recursos da versão web.

### LLM

O app escolhe o modelo assim:

1. Se `OPENAI_API_KEY` estiver definida, usa a OpenAI (padrão: `gpt-4o-mini`).
2. Caso contrário, usa o [Ollama](https://ollama.com) local (padrão: `gemma3` em `http://localhost:11434`).

### Requisitos

- Node.js **22.x**
- FFmpeg: já incluído via `ffmpeg-static`; se não estiver disponível, o app usa o `ffmpeg` do PATH
- Opcional: Ollama, se não for usar a OpenAI
- Opcional: [whisper.cpp](https://github.com/ggerganov/whisper.cpp) para transcrever o áudio dos vídeos

### Como rodar localmente

```bash
git clone https://github.com/yagodejesus/ecoa-saude.git
cd ecoa-saude
npm install
```

Crie um arquivo `.env` na raiz (veja as variáveis abaixo) e inicie o servidor:

```bash
npm start
```

Acesse em `http://localhost:3000`. O banco SQLite (`verifacts.db`) é criado automaticamente na primeira execução.

### Variáveis de ambiente

| Variável | Padrão | Descrição |
| --- | --- | --- |
| `PORT` | `3000` | Porta do servidor |
| `NODE_ENV` | — | Use `production` em produção (cookies seguros e alertas de configuração) |
| `APP_URL` | `http://localhost:PORT` | URL pública, usada nos links de redefinição de senha |
| `SESSION_SECRET` | valor de dev | **Obrigatória em produção.** Segredo das sessões |
| `DB_PATH` | `./verifacts.db` | Caminho do banco SQLite |
| `ADMIN_EMAILS` | — | E-mails com acesso ao `/admin`, separados por vírgula |
| `OPENAI_API_KEY` | — | Chave da OpenAI. Sem ela, o app usa o Ollama |
| `OPENAI_MODEL` | `gpt-4o-mini` | Modelo da OpenAI |
| `OLLAMA_HOST` | `http://localhost:11434` | Endereço do Ollama |
| `OLLAMA_MODEL` | `gemma3` | Modelo do Ollama |
| `GOOGLE_FACTCHECK_API_KEY` | — | Chave da Google Fact Check Tools API |
| `MAX_NEWS_ITEMS` | `15` | Máximo de notícias consultadas por verificação |
| `NEWS_LOOKBACK_DAYS` | `90` | Janela de busca de notícias, em dias |
| `MAX_SCRAPED_CHARS` | `5000` | Limite de caracteres extraídos de um link |
| `MAX_VIDEO_FRAMES` | `6` | Máximo de frames analisados por vídeo |
| `FRAME_INTERVAL_SECONDS` | `8` | Intervalo entre frames extraídos |
| `WHISPER_COMMAND` | — | Executável do whisper.cpp |
| `WHISPER_MODEL` | — | Caminho do modelo do Whisper |
| `TEMP_DIR` | `./tmp` | Pasta de arquivos temporários e uploads |
| `SMTP_HOST` / `SMTP_PORT` | — / `587` | Servidor SMTP para os e-mails de recuperação de senha |
| `SMTP_USER` / `SMTP_PASS` | — | Credenciais SMTP |
| `SMTP_FROM` | `SMTP_USER` | Remetente dos e-mails |

Sem SMTP configurado, o link de redefinição de senha é impresso no log do servidor.

Exemplo mínimo de `.env`:

```env
SESSION_SECRET=troque-por-um-valor-aleatorio-longo
OPENAI_API_KEY=sk-...
GOOGLE_FACTCHECK_API_KEY=...
ADMIN_EMAILS=admin@exemplo.com
```

### Deploy no Railway

1. Crie um serviço a partir deste repositório; o comando de start é `npm start`.
2. Defina as variáveis de ambiente, no mínimo `NODE_ENV=production`, `SESSION_SECRET` e `APP_URL`.
3. Monte um **Volume** (por exemplo em `/data`) e defina `DB_PATH=/data/verifacts.db`. Sem isso, o banco é apagado a cada deploy.
4. Use `GET /health` como health check.

### API mobile

Todas as rotas abaixo, exceto as de autenticação, exigem o header `Authorization: Bearer <token>`.

| Método | Rota | Descrição |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Cria conta (`email`, `password`) e retorna o token |
| `POST` | `/api/auth/login` | Faz login e retorna o token |
| `GET` | `/api/me` | Dados do usuário logado |
| `POST` | `/api/verify` | Verifica um texto ou link (`content`) |
| `POST` | `/api/verify/image` | Verifica uma imagem (multipart, campo `file`) |
| `POST` | `/api/verify/video` | Verifica um vídeo (multipart, campo `file`) |
| `GET` | `/api/history` | Lista o histórico |
| `GET` | `/api/history/:id/result` | Resultado completo de um item do histórico |
| `DELETE` | `/api/history/:id` | Remove um item do histórico |
| `DELETE` | `/api/history` | Limpa o histórico |
| `POST` | `/api/push/register` | Registra o token de push (Expo) do aparelho |
| `GET` | `/api/account` | Dados da conta |
| `POST` | `/api/account/profile` | Atualiza o perfil |
| `POST` | `/api/account/password` | Troca a senha |
| `POST` | `/api/account/delete` | Exclui a conta |

Uploads aceitam apenas imagem ou vídeo, com até 80 MB.

### Segurança

- Senhas com hash bcrypt.
- Sessões guardadas no SQLite, com cookies `httpOnly`.
- Rate limit por IP no login, no cadastro e na recuperação de senha.
- Tokens de redefinição de senha valem 1 hora e só podem ser usados uma vez.

### Limitações

A detecção de IA em imagens usa **heurísticas**, não um modelo treinado, e pode errar nos dois sentidos. Os vereditos de checagem dependem das evidências encontradas e do LLM usado. Trate os resultados como apoio à verificação, não como prova definitiva.

### Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE.txt).
