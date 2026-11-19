# Ecoa Saúde

**English** | [Português](README.pt-BR.md)

A **fact-checking** and **AI-generated content detection** platform for text, links, images and videos. Users submit content and get a verdict (likely false, suspicious, unverified or likely true), with an explanation, related fact-checks and recent news on the topic.

The project is a single-file Node.js/Express server ([app.js](app.js)) that serves the web interface and a REST API for the mobile app. The interface and prompts are in Brazilian Portuguese.

## Features

- **Text and link checking**: extracts the main claim, gathers evidence and classifies the content with an LLM.
  - For links, the page is downloaded and its text is extracted with Cheerio.
  - Evidence comes from the [Google Fact Check Tools API](https://developers.google.com/fact-check/tools/api) and Google News (RSS, pt-BR).
- **AI detection in images**: heuristic analysis using several techniques (EXIF metadata, gradients, bloom/halo, contrast, lighting, artifacts, edges, banding, entropy, format, etc.), with a heatmap and a per-technique breakdown.
- **Video analysis**: extracts frames with FFmpeg, runs AI detection on each one and, if Whisper is configured, transcribes the audio for fact-checking.
- **User accounts**: sign-up, login, password recovery by e-mail, profile editing, password change and account deletion.
- **Per-user history**: stores the last 20 checks with the full result, so they can be reopened without running the analysis again.
- **Admin panel** (`/admin`): metrics, activity log, push notifications (Expo) and CSV data export.
- **Mobile API** (`/api/*`): Bearer token authentication and the same features as the web version.

## LLM

The app picks the model as follows:

1. If `OPENAI_API_KEY` is set, it uses OpenAI (default: `gpt-4o-mini`).
2. Otherwise, it uses a local [Ollama](https://ollama.com) instance (default: `gemma3` at `http://localhost:11434`).

## Requirements

- Node.js **22.x**
- FFmpeg: bundled via `ffmpeg-static`; if unavailable, the app falls back to `ffmpeg` on the PATH
- Optional: Ollama, if you are not using OpenAI
- Optional: [whisper.cpp](https://github.com/ggerganov/whisper.cpp) to transcribe video audio

## Running locally

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

## Environment variables

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

## Deploying to Railway

1. Create a service from this repository; the start command is `npm start`.
2. Set the environment variables, at least `NODE_ENV=production`, `SESSION_SECRET` and `APP_URL`.
3. Mount a **Volume** (for example at `/data`) and set `DB_PATH=/data/verifacts.db`. Without it, the database is wiped on every deploy.
4. Use `GET /health` as the health check.

## Mobile API

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

## Security

- Passwords hashed with bcrypt.
- Sessions stored in SQLite, with `httpOnly` cookies.
- Per-IP rate limiting on login, sign-up and password recovery.
- Password reset tokens expire after 1 hour and can only be used once.

## Limitations

AI detection in images relies on **heuristics**, not a trained model, and can be wrong in both directions. Fact-check verdicts depend on the evidence found and on the LLM used. Treat the results as an aid to verification, not as definitive proof.

## License

Distributed under the MIT License. See [LICENSE](LICENSE).
