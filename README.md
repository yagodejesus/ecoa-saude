# Ecoa Saúde

Plataforma de **verificação de fatos** e **detecção de conteúdo gerado por IA** em textos, links, imagens e vídeos. O usuário envia um conteúdo e recebe um veredito (provavelmente falso, suspeito, não verificado ou provavelmente verdadeiro), com justificativa, checagens de fatos relacionadas e notícias recentes sobre o assunto.

O projeto é um servidor Node.js/Express de arquivo único ([app.js](app.js)) que serve a interface web e uma API REST para o app mobile.

## Funcionalidades

- **Checagem de textos e links**: extrai a alegação principal, busca evidências e classifica o conteúdo com um LLM.
  - Para links, a página é baixada e o texto é extraído com Cheerio.
  - Evidências vêm da [Google Fact Check Tools API](https://developers.google.com/fact-check/tools/api) e do Google News (RSS, pt-BR).
- **Detecção de IA em imagens**: análise heurística com várias técnicas (metadados EXIF, gradientes, bloom/halo, contraste, iluminação, artefatos, bordas, banding, entropia, formato etc.), com mapa de calor e detalhamento de cada técnica.
- **Análise de vídeos**: extrai frames com FFmpeg, roda a detecção de IA em cada um e, se o Whisper estiver configurado, transcreve o áudio para a checagem.
- **Contas de usuário**: cadastro, login, recuperação de senha por e-mail, edição de perfil, troca de senha e exclusão de conta.
- **Histórico por usuário**: guarda as últimas 20 verificações com o resultado completo, para reabrir sem refazer a análise.
- **Painel administrativo** (`/admin`): métricas, log de atividades, envio de notificações push (Expo) e exportação de dados em CSV.
- **API mobile** (`/api/*`): autenticação por token Bearer e os mesmos recursos da versão web.

## LLM

O app escolhe o modelo assim:

1. Se `OPENAI_API_KEY` estiver definida, usa a OpenAI (padrão: `gpt-4o-mini`).
2. Caso contrário, usa o [Ollama](https://ollama.com) local (padrão: `gemma3` em `http://localhost:11434`).

## Requisitos

- Node.js **22.x**
- FFmpeg: já incluído via `ffmpeg-static`; se não estiver disponível, o app usa o `ffmpeg` do PATH
- Opcional: Ollama, se não for usar a OpenAI
- Opcional: [whisper.cpp](https://github.com/ggerganov/whisper.cpp) para transcrever o áudio dos vídeos

## Como rodar localmente

```bash
git clone <url-do-repositorio>
cd "Ecoa Saude app"
npm install
```

Crie um arquivo `.env` na raiz (veja as variáveis abaixo) e inicie o servidor:

```bash
npm start
```

Acesse em `http://localhost:3000`. O banco SQLite (`verifacts.db`) é criado automaticamente na primeira execução.

## Variáveis de ambiente

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

## Deploy no Railway

1. Crie um serviço a partir deste repositório; o comando de start é `npm start`.
2. Defina as variáveis de ambiente, no mínimo `NODE_ENV=production`, `SESSION_SECRET` e `APP_URL`.
3. Monte um **Volume** (por exemplo em `/data`) e defina `DB_PATH=/data/verifacts.db`. Sem isso, o banco é apagado a cada deploy.
4. Use `GET /health` como health check.

## API mobile

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

## Segurança

- Senhas com hash bcrypt.
- Sessões guardadas no SQLite, com cookies `httpOnly`.
- Rate limit por IP no login, no cadastro e na recuperação de senha.
- Tokens de redefinição de senha valem 1 hora e só podem ser usados uma vez.

## Limitações

A detecção de IA em imagens usa **heurísticas**, não um modelo treinado, e pode errar nos dois sentidos. Os vereditos de checagem dependem das evidências encontradas e do LLM usado. Trate os resultados como apoio à verificação, não como prova definitiva.

## Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE).
