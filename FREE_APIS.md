# FREE_APIS.md: free API keys and services for IdentityShield v3

**Read this first**

- **No real keys are included in this kit** (and none should ever be shared in chat or committed). Each entry tells you where to sign up for your own free key.
- **Everything is optional.** IdentityShield v3 runs fully offline. Keys only add enrichment, AI narratives, email or the ngrok tunnel.
- Put every key in `.env` (git-ignored). Never paste a key into code, the generator page source, slides or screenshots.
- Free limits change. The limits below were checked on 30 Oct 2026 where marked ✓; others are approximate. Check the provider's page when you sign up.
- **Privacy rule (context.md §15):** send only IP addresses to enrichment providers. Never send user names, emails, access keys or log lines.
- **Hackathon rule:** these services are for enrichment, narration, alerts and tunneling only. Enforcement still goes through the supplied simulator.

---

## 1. Tunnel (needed for the two-laptop demo)

| Service | What we use it for | Free tier | Key / setup | `.env` name |
|---|---|---|---|---|
| **ngrok** ✓ | Public HTTPS URL for the ingest service (port 8001) so laptop 2 can send signed events | 3 endpoints online, 1 auto-assigned dev domain (stays the same), 1 GB/month data out, **20,000 HTTP requests/month**, 4,000 requests/min | Sign up at ngrok.com → Dashboard → "Your Authtoken" → run `ngrok config add-authtoken <token>` once | `NGROK_AUTHTOKEN` (documentation only; the ngrok agent stores it in its own config) |

**Budget warning:** 20,000 requests per month is enough for the demo, but not for running background noise for hours. Send noise as **batches** (for example, 20 events every 3 s is 1,200 requests/hour) and switch noise off when you're not rehearsing.

**Browser warning page:** the free plan may show an ngrok warning page to browsers. The generator adds the header `ngrok-skip-browser-warning: true` to API calls, which skips it.

Sources: [ngrok pricing limits](https://ngrok.com/docs/pricing-limits)

---

## 2. IP enrichment and threat intelligence (Agent 3, optional)

| Provider | What it adds | Free tier | Key needed? | `.env` name | Provider ID in `ENRICH_PROVIDERS` |
|---|---|---|---|---|---|
| **IPinfo Lite** ✓ | ASN, AS name, AS domain, country, continent | Free and unlimited (API and downloadable database) | Yes, free token on signup | `IPINFO_TOKEN` | `ipinfo_lite` |
| **ip-api.com** | City, lat/lon, ISP, ASN, proxy/hosting flags | About 45 requests/min, HTTP only, non-commercial use | No | none | `ipapi` |
| **AbuseIPDB** ✓ | Abuse confidence score, report count, usage type (hosting, ISP) | 1,000 IP checks per day | Yes, free account | `ABUSEIPDB_KEY` | `abuseipdb` |
| **GreyNoise Community** | Is this IP a known internet scanner (noise) or a known benign service? | Roughly 50 lookups/day without a key; more with a free registered key (approximate) | Optional | `GREYNOISE_KEY` | `greynoise` |
| **AlienVault OTX** | IP and domain indicators from community threat pulses | Free with account | Yes, free account | `OTX_KEY` | `otx` |
| **VirusTotal (public API)** | IP reputation from many engines | About 4 requests/min and 500/day; public API is non-commercial | Yes, free account | `VT_KEY` | `virustotal` (not wired by default) |
| **Shodan InternetDB** | Open ports and tags for an IP | Free, no key | No | none | `internetdb` (not wired by default) |
| **Tor bulk exit list** | Current Tor exit IPs | Free, no key; refresh daily into `app/v3/data/tor_exits.txt` | No | none | offline list |
| **MaxMind GeoLite2** | Offline city/ASN database file (no per-request calls) | Free with account and license key | Yes, free license key | `MAXMIND_LICENSE_KEY` | offline database (best for the venue: no internet needed after download) |

**Recommended for the demo:**
- **IPinfo Lite** for ASN and country.
- **AbuseIPDB** for reputation.
- Optionally the **MaxMind GeoLite2** database downloaded before the event, so enrichment works with no internet.
- Keep `ENRICH_PROVIDERS` empty during the official metrics run, so results are reproducible offline.

Sources: [IPinfo Lite announcement](https://ipinfo.io/blog/ipinfo-lite-free-accurate-unlimited-ip-data) · [AbuseIPDB pricing](https://abuseipdb.com/pricing) · [GreyNoise free API overview (third-party article)](https://dev.to/0012303/greynoise-has-a-free-api-see-if-an-ip-is-scanning-the-internet-not-just-you-2af8)

---

## 3. LLM for case narratives (Agent 13, optional)

The LLM only writes the explanation text. It never computes scores or chooses actions, and it gets log text as quoted untrusted data (context.md §2 rule 8, PRD §15.3).

| Provider | Free option | Key | `.env` names | Notes |
|---|---|---|---|---|
| **Ollama (local)** | Free, runs on your laptop (e.g. a small 3–8B model) | None | `LLM_PROVIDER=ollama`, `OLLAMA_URL=http://127.0.0.1:11434` | Best for the venue: no internet, no key. Pull the model before the event. |
| **Google Gemini API (AI Studio)** | Free tier with rate limits | Free API key from Google AI Studio | `LLM_PROVIDER=gemini`, `GEMINI_API_KEY` | Free-tier data may be used by Google to improve products; send only the structured case. |
| **Groq** | Free tier with rate limits, very fast | Free API key | `LLM_PROVIDER=groq`, `GROQ_API_KEY` | Good latency for live demos |
| **OpenRouter** | Some models marked ":free" | Free API key | `LLM_PROVIDER=openrouter`, `OPENROUTER_API_KEY` | Availability of free models changes |

Set `LLM_ENABLED=true` only after the template narrative works. If the LLM is slow or offline, the system falls back to templates within 5 s.

---

## 4. Email alerts to the admin (Notifier, optional)

| Service | Free tier | Key | `.env` names |
|---|---|---|---|
| **Gmail SMTP** | Free; needs 2-Step Verification and an **App Password** | App Password (16 characters) | `EMAIL_MODE=smtp`, `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_USER`, `SMTP_PASSWORD`, `ADMIN_EMAIL` |
| **Brevo (SMTP relay)** | About 300 emails/day | SMTP key | same names, host from Brevo dashboard |
| **Resend** | About 3,000 emails/month (100/day) | API key | use the SMTP credentials Resend provides |
| **Outbox mode** | No email sent; messages saved and shown on the Notifications page | None | `EMAIL_MODE=outbox` (safest for the demo if Wi-Fi is unreliable) |

---

## 5. Optional real data sources (read-only, NOT for enforcement)

| Service | Free option | Use | Rule |
|---|---|---|---|
| **Okta Integrator Free Plan** (developer org) | Free developer org | Generate real Okta System Log events by logging in yourself, then export them as test data | Read logs only. Never modify any production tenant. |
| **AWS Free Tier / CloudTrail Event history** | 90 days of management events viewable at no cost | Export sample CloudTrail events from your own sandbox account | Read-only. No attacks against real accounts; the hackathon forbids modifying live accounts. |

For the hackathon demo, the **generator website** is the recommended live source. It needs no cloud account.

---

## 6. `.env` template (names only, values empty)

The kit includes `env.example.txt` with every variable. Copy it to `.env` in the project root and fill in only what you use.

---

## 7. Security checklist for keys

- `.env` is listed in `.gitignore`; `git status` never shows it.
- Never paste keys into Antigravity chats; refer to them by variable name.
- Rotate any key that appears on a projector, screenshot or commit.
- The generator's HMAC secret is typed into a password field on laptop 2 and kept only in memory.
- Different HMAC secrets for rehearsal and the final demo (`INGEST_KEYS` supports several key IDs).
