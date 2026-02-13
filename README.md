## 🛡️ Blip Endpoint Sentinel

**Indigenous Endpoint Security for the GenAI Era.**

Blip Endpoint Sentinel is a lightweight OS‑level security agent that silently monitors your clipboard and stops sensitive data from leaking into GenAI tools (ChatGPT, Gemini, Copilot, etc.) or external apps.

It works in two modes:

- **STANDARD (Sovereign & Offline)** – Fast regex DLP for Indian IDs and developer secrets; no data ever leaves the device.
- **ENTERPRISE (AI & RAG Powered)** – Adds code‑logic leak detection (RAG over a local “secret codebase”) and AI‑powered sanitization + explanations using Google Gemini.

---

## ✨ Core Features

- **Clipboard DLP for Text**
  - Detects **Aadhaar, PAN, GSTIN, Indian mobiles, UPI‑style numbers**.
  - Detects **AWS keys, Google API keys, DB URLs, private key blocks**.
  - Blocks / warns / logs based on a **policy‑as‑code engine**.

- **Clipboard DLP for Images (Screenshots) – Enterprise mode**
  - Watches the clipboard for real images (Snipping Tool, Win+Shift+S, Copy Image).
  - Uses **Gemini Vision** to decide if the screenshot contains sensitive text (IDs, code, secrets).
  - Pops the same security UI and lets you block risky screenshots before they hit ChatGPT.

- **Company‑Specific Code Leak Protection (RAG) – Enterprise mode**
  - Embeds a local “secret codebase” into **ChromaDB + Sentence Transformers**.
  - When you copy code, Blip checks **semantic similarity** against these secrets.
  - Even if you **rename variables or slightly change structure**, it can still flag a match.

- **AI‑Powered Sanitization – Enterprise mode**
  - Gemini rewrites the clipboard content by redacting secrets (API keys, Aadhaar, etc.).
  - You get a one‑click **“✨ SANITIZE & PASTE”** button that keeps your workflow smooth.

- **Explainable Alerts**
  - Popups show not just “blocked” but also:
    - **Why unsafe** (short explanation).
    - **Safe alternative** (“use IAM roles instead of pasting keys,” etc.).

- **Admin Dashboard**
  - CustomTkinter dashboard with:
    - Total / blocked / allowed / sanitized counts.
    - Top users, top threat types, policy enforcement mix.
    - Filters: by user, action, source (text/image), and time window.
    - Recent incidents table (time, user, action, type, risk, source, policy).

- **Policy‑as‑Code (JSON)**
  - Security teams choose behavior via `policies/*.json`:
    - Match on `threat_type`, `source`, etc.
    - Set `risk_level` and `enforcement` (`BLOCK`, `WARN`, `LOG`).
  - Example policies: `default`, `india-govt`, `startup-enterprise`.

---

## 📦 Tech Stack

- **Language**: Python 3.10+ recommended
- **Clipboard & UI**
  - `pyperclip` for clipboard text
  - `Pillow.ImageGrab` for clipboard images on Windows
  - `customtkinter` for modern dark‑mode popups and dashboard
  - `plyer` for toast notifications
  - `pystray` (reserved for tray icon, optional)
- **AI & RAG**
  - `sentence-transformers` (`all-MiniLM-L6-v2`) + `chromadb` for local semantic search
  - `google-generativeai` for Gemini 1.5/2.5 text + vision
- **Config & Logging**
  - `python-dotenv` for `.env` configuration
  - JSON logs under `logs/threats.json`

---

## 🔧 Installation

1. **Clone the repo**

```bash
git clone <your-repo-url>
cd "Blip OS integrated"
```

2. **(Recommended) Create and activate a virtual environment**

```bash
python -m venv .venv

# PowerShell
.venv\Scripts\Activate.ps1
```

3. **Install dependencies**

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

> If `Pillow` build fails, run:
> ```bash
> python -m pip install --only-binary=:all: Pillow
> python -m pip install -r requirements.txt
> ```

---

## ⚙️ Configuration

Blip uses `.env` + environment variables.

Create a `.env` file at the project root:

```env
# Only needed for ENTERPRISE mode
GEMINI_API_KEY=your_real_gemini_key_here
```

### Modes

- `BLIP_MODE`
  - `STANDARD` (default): offline regex DLP only.
  - `ENTERPRISE`: RAG + Gemini AI + image analysis enabled.

Example (PowerShell, for current session):

```powershell
$env:BLIP_MODE = "STANDARD"      # or "ENTERPRISE"
```

### Policies

- `BLIP_POLICY` chooses which JSON policy to load from `policies/`:
  - `default` – basic behavior mirroring the hard‑coded defaults.
  - `india-govt` – strict, blocks Aadhaar/PAN/GST outright.
  - `startup-enterprise` – friendlier, more WARN + SANITIZE, less hard blocking.

Example:

```powershell
$env:BLIP_POLICY = "india-govt"
```

### Notifications

- `BLIP_SHOW_TOASTS`
  - `true` (default) – show system notifications via `plyer`.
  - `false` – disable toasts.

```powershell
$env:BLIP_SHOW_TOASTS = "false"
```

---

## 🚀 Running Blip

### 1. STANDARD Mode (Sovereign & Offline)

Use this for **GovTech / high‑sovereignty** scenarios.

1. Ensure **no** `GEMINI_API_KEY` is set (or just keep `BLIP_MODE=STANDARD`).

2. Start the Sentinel:

```powershell
cd "G:\HACKATHONS\Blip OS integrated"
$env:BLIP_MODE = "STANDARD"
python main.py
```

You should see:

```text
Blip Endpoint Sentinel Active in STANDARD (Offline Regex) mode...
```

3. Test:
   - Copy: `2345 6789 1234` (valid Aadhaar pattern).
   - A popup appears:
     - Type: `Aadhaar Number`
     - Risk: `HIGH` / `CRITICAL` (depending on policy)
   - **BLOCK** → clipboard is wiped, incident logged.
   - **ALLOW** → clipboard stays, incident logged as allowed.
   - **SANITIZE** → In STANDARD mode, sanitize is disabled (offline guarantee); popup explains that AI sanitize is Enterprise‑only.

> In STANDARD mode:
> - No Gemini calls
> - No RAG / embeddings calls (unless you explicitly switch to ENTERPRISE)

---

### 2. ENTERPRISE Mode (AI & RAG Powered)

Use this for **startups and enterprises** where AI is allowed but needs governance.

1. Set your `GEMINI_API_KEY` in `.env`:

```env
GEMINI_API_KEY=your_real_gemini_key_here
```

2. Start in ENTERPRISE mode:

```powershell
cd "G:\HACKATHONS\Blip OS integrated"
$env:BLIP_MODE = "ENTERPRISE"
$env:BLIP_POLICY = "startup-enterprise"   # or "india-govt" / "default"
python main.py
```

You should see:

```text
Blip Endpoint Sentinel Active in ENTERPRISE (AI + RAG) mode...
⚡ Loading Enterprise RAG Engine (Embeddings)...
...
```

#### 2.1 AI Sanitization Example

1. Copy text containing a secret, e.g.:

```text
My AWS key is AKIAABCDEFGHIJKLMNOP, please debug this error.
```

2. Popup shows:
   - Type: `AWS Access Key`
   - Risk: e.g. `HIGH`
   - Policy enforcement: `(WARN)` or `(BLOCK)` depending on `BLIP_POLICY`.
   - Extra explanation block:
     - `Why unsafe: ...`
     - `Safe alternative: ...`

3. Click **✨ SANITIZE & PASTE**:
   - Blip calls Gemini with a strict DLP prompt.
   - Clipboard is replaced with a redacted version, for example:
     - `My AWS key is [REDACTED_API_KEY], please debug this error.`

#### 2.2 RAG Code Leak Example

`core/rag_engine.py` indexes a set of “secret” code snippets into a local **ChromaDB**.

To customize it for your company:

1. Edit `core/rag_engine.py`, function `_load_mock_secrets()`.
2. Replace demo snippets with your own proprietary functions/algorithms (short chunks).
3. Delete the existing vector DB once to reindex:

```powershell
Remove-Item -Recurse -Force .\data\vector_db
```

4. Restart Blip in ENTERPRISE mode.

Demo flow:

1. Copy a **modified** version of one of those secret functions (rename variables, tweak comments).
2. Blip:
   - Computes embedding.
   - Finds a close match in ChromaDB.
   - Raises `🚫 PROPRIETARY CODE LEAK` with detail like:
     - `Matches Internal Codebase (Dist: 0.23) Ref: def compute_pagerank(...`
3. Again, popup includes:
   - Risk level + policy mode.
   - “Why unsafe / Safe alternative” (e.g., share pseudocode, not raw implementation).

#### 2.3 Image (Screenshot) DLP Example

1. Ensure ENTERPRISE mode and valid `GEMINI_API_KEY`.

2. Take a screenshot that includes:
   - Source code, or
   - A mock of an ID / financial data.

3. Use **Win + Shift + S** (or Snipping Tool → Copy) to send it to clipboard.

4. Blip:
   - Calls `ImageGrab.grabclipboard()` and sees an image.
   - Sends it to Gemini Vision with a DLP prompt.
   - If Gemini says it’s sensitive, you get:
     - Type: `🖼️ SENSITIVE IMAGE CONTENT`
     - Risk: `HIGH`
     - Explanation (why unsafe / safe alternative).

5. Actions:
   - **BLOCK** → wipes the image from the clipboard.
   - **ALLOW** → keeps it, logs an allowed incident.
   - **SANITIZE** → for images, currently behaves as a safe BLOCK (we cannot rewrite the image itself yet).

---

## 🧩 Policy-as-Code (JSON)

Policies live in the `policies/` directory and are selected via:

```powershell
$env:BLIP_POLICY = "india-govt"        # loads policies/india-govt.json
```

Each policy contains a list of rules:

```jsonc
{
  "name": "India Govt Policy",
  "rules": [
    {
      "match": { "threat_type": "Aadhaar Number" },
      "risk_level": "CRITICAL",
      "enforcement": "BLOCK"
    },
    {
      "match": { "source": "image" },
      "risk_level": "HIGH",
      "enforcement": "BLOCK"
    },
    {
      "match": { "threat_type": "*" },
      "enforcement": "BLOCK"
    }
  ]
}
```

- `match` – fields to match from the threat (e.g. `threat_type`, `source`).
- `risk_level` – overrides risk label (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`).
- `enforcement`:
  - `BLOCK` – popup with strong red header; blocking is encouraged.
  - `WARN` – same popup but semantically a “soft” policy.
  - `LOG` – no popup; incident is logged silently.

The first matching rule wins. If nothing matches, Blip falls back to **BLOCK** with the threat’s default risk.

---

## 📊 Admin Dashboard

To view analytics:

```powershell
cd "G:\HACKATHONS\Blip OS integrated"
python main.py --dashboard
```

You’ll see:

- **Filter bar**:
  - User (`All` / `user@host`),
  - Action (`BLOCKED`, `ALLOWED`, `SANITIZED`, `LOGGED`),
  - Source (`text`, `image`),
  - Time range (`Last 24h`, `Last 7 days`, etc.).
- **Stats cards**: total / blocked / allowed / sanitized.
- **Breakdown**: top users, top threat types (with mini bars), policy enforcement mix.
- **Recent incidents table**: time, user, action, type, risk, source, policy.

Logs are stored in `logs/threats.json` as an array of JSON objects.

---

## 🧪 Quick Testing Checklist

- STANDARD mode:
  - Copy Aadhaar / PAN / AWS key → popup appears, SANITIZE disabled, fully offline.
- ENTERPRISE mode:
  - Copy AWS key → popup + explanation + working SANITIZE.
  - Copy code similar to your RAG secrets → `🚫 PROPRIETARY CODE LEAK`.
  - Copy screenshot with code → `🖼️ SENSITIVE IMAGE CONTENT`.
  - Check `python main.py --dashboard`:
    - Filters work.
    - Policy enforcement mix reflects your chosen `BLIP_POLICY`.

---

## 📝 Notes & Limitations

- Current implementation focuses on **Windows** (because of `ImageGrab.grabclipboard` and some UX assumptions).
- Image sanitization is implemented as **safe blocking** rather than rewriting images.
- System tray icon is wired via dependencies but not yet fully exposed in the UI.

---

## 🤝 Contributing

Ideas to extend:

- Per‑application policies (different rules for browser vs IDE).
- Multi‑endpoint aggregation (central dashboard).
-, more advanced explainability and in‑app training tips.

PRs and issues are welcome!

