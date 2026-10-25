# GA5 Question 3: Safe AI Mailroom — beginner's implementation

**This is a runnable reference implementation, not a guaranteed 4/4 solution.** It includes local tests of the API contract, but its AI decisions have NOT been evaluated on the grader's private dossiers, and external Upstash/OpenRouter integration must still be tested with your own credentials. It does not send real customer email; its `commit` records receipt-authorized effects in the agent's durable evaluation state, as specified by this synthetic exercise.

## 1. What it does (plain language)

- `propose`: read 64 dossiers (58 stable + 6 fresh), ask AI to choose one of 6 allowed actions and cite specific lines, calculate canonical SHA-256, save each decision and evaluation, return `awaiting_receipts`.
- `commit`: compare each receipt to its original proposal, verify its Ed25519 signature using **that evaluation's** public key, save all valid receipts together and return `completed`.
- If **any** signature is wrong, the entire commit fails without saving any of them.
- Replaying a request uses stored answers. Reusing an evaluation ID with changed content is an HTTP 409 conflict.
- Stable dossier decisions are cached by ID + entire canonical dossier content, not evaluation ID.

## 2. Files in the project

| File | Purpose |
|---|---|
| `app.py` | HTTP API, validation, hashes, Ed25519 receipt verification, replay and conflicts |
| `policy.py` | Calls AI in groups; checks model output against strict action/target/payload/evidence schemas |
| `store.py` | Durable Redis storage using Upstash HTTPS REST API |
| `requirements.txt` | Python packages |
| `tests/test_contract.py` | Offline tests (do not use AI, money, Check, or Save) |
| `.env.example` | Environment-variable names; **not actual secrets** |
| `vercel.json` | Set serverless function timeout to 60 seconds |

## 3. Get your credentials

### AI key

1. Visit <https://openrouter.ai/> and register/sign in.
2. Go to <https://openrouter.ai/settings/keys> and create an API key.
3. The default model is `openai/gpt-4.1-mini` (paid, low cost). Add credit if required. Cost, limits and availability can change.
4. Save the token privately. **Do not add it to GitHub, the endpoint URL, or the assignment answer.**
5. Your previously exhausted/invalid AI Pipe token will **not** work as an OpenRouter API key.

### Durable database

1. Visit <https://console.upstash.com/> and create a Redis database.
2. In the Redis database page find the **REST URL** and **REST Token**. They must be the writable credentials, not the Read Only token.
3. Save them privately. The database stores decisions, receipt verification keys, receipts, and evaluation outcomes.

## 4. Run the offline tests first (no API key required)

Open the extracted project folder in VS Code and open **Terminal > New Terminal**. These PowerShell commands are suitable on Windows:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
```

Expected output: **9 passed** (the exact timing will vary). If PowerShell refuses to activate the virtual environment, run these instead:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pytest -q
```

`pytest` mocks the AI and Redis to test the protocol, so success does **not** yet establish accuracy on the 64 dossiers.

## 5. Start the local server (optional)

```powershell
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000/>. Expect a JSON response with `"status":"ready"`.

The important POST endpoint is **`http://127.0.0.1:8000/mailroom`** locally. Do **not** put this localhost URL in the exam; the exam requires public HTTPS.

## 6. Upload to GitHub

1. Create a new **private** repository at <https://github.com/new>, e.g. `safe-ai-mailroom`.
2. From inside the project folder, run (replace `YOUR_USERNAME`):

```powershell
git init
git add .
git commit -m "Mailroom contract implementation"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/safe-ai-mailroom.git
git push -u origin main
```

3. `.gitignore` excludes `.env`, `.venv`, and local temporary files. Make sure no real API keys are included in the repository.

## 7. Deploy on Vercel

1. Go to <https://vercel.com/new> and import your GitHub repo.
2. Leave the root directory as the project root, which contains `app.py`.
3. Add these **environment variables** under the Vercel project's **Settings > Environment Variables**:

| Name | Value |
|---|---|
| `OPENROUTER_API_KEY` | Your actual OpenRouter key |
| `MAILROOM_MODEL` | `openai/gpt-4.1-mini` |
| `UPSTASH_REDIS_REST_URL` | Redis REST HTTPS URL |
| `UPSTASH_REDIS_REST_TOKEN` | Redis standard write token |
| `MAILROOM_BATCH_SIZE` | `4` |
| `MAILROOM_WORKERS` | `8` |

4. Deploy. If you changed environment variables after an earlier deployment, redeploy so the running function sees them.
5. Open `https://YOUR-PROJECT.vercel.app/` in a browser. A health JSON response indicates FastAPI is live.
6. **Submit `https://YOUR-PROJECT.vercel.app/mailroom`** into the exam field (no ending query string, fragment, or credentials).

Important: a simple browser visit is a GET; the grader performs POST requests with the full JSON bodies. Do **not** use the browser health response to assume the AI, database, or receipt flow works end to end.

## 8. BEFORE using a graded Check

- Confirm **9 unit tests pass**.
- Confirm Vercel health endpoint is reachable without a login or redirect.
- Confirm the Upstash credentials are correct and writable.
- Confirm the OpenRouter API key has usable model access/credit.
- Look at Vercel project logs for any error after a POST. Do not paste private tokens or full dossier contents into public issue reports.
- If the grader reports that the first request times out, reduce batching/concurrency only after checking model and provider latency. You have **55 seconds per request**, and the model work must occur inside the deployment, not ChatGPT's interactive session.
- Ensure **Check** and **Save** budget is understood: 10 total; keep the last one for Save.

## 9. Common errors

| Error | Meaning / remedy |
|---|---|
| `401` from OpenRouter | Missing, invalid, or exhausted **OpenRouter** token; check provider dashboard |
| `503 Persistent database unavailable` | Missing Upstash env vars, invalid token, or unreachable REST endpoint |
| `503 Model decisions unavailable or invalid` | Model access, timeout, JSON format, or incorrect evidence/action; inspect private logs |
| `409 Evaluation content conflict` | Same evaluation ID was reused with a changed `propose` request |
| `409 Receipt does not match proposal` | Wrong evaluation, call ID, action, or proposal digest |
| `422 Invalid signed receipt` | Receipt was changed, corrupt, or signed by the wrong key |
| `404` on `/` or `/mailroom` | Check the deployed app/route and that Vercel discovered root `app.py` |
| `307` | A redirected URL is being used; paste the exact `/mailroom` route without slash |

## 10. Important limitations / grading notes

1. The **expected classification on hidden cases cannot be determined from the question alone**. AI output needs real Check feedback for accuracy refinement.
2. There is **no static answer table**. Fresh audit cases must be processed by the model each run.
3. `openai/gpt-4.1-mini` is only a suggested model; the evaluator does not award points for its name.
4. Do not replace cryptographic verification with `accepted == true`; the signature proves who issued the receipt.
5. `send_approved_notice` is HIGH RISK. A signed approval for recipient A or a previous order state is NOT authority to email recipient B about a newer state.
6. The tests don't exercise live external credentials or the grader's 58+6 real dossiers. **Don't claim full marks until the examiner's Check response confirms them.**
7. The sample uses Redis with atomic NX and compare-and-swap to resist repeated calls. Real production payment/email tools would need separate transactional outbox/idempotency safeguards; the grader's receipt is used as the exercise's authoritative effect result.

## 11. References

- <https://vercel.com/docs/frameworks/backend/fastapi>
- <https://vercel.com/docs/functions/configuring-functions/duration>
- <https://upstash.com/docs/redis/features/restapi>
- <https://openrouter.ai/docs/api/api-reference/chat/send-chat-completion-request>
