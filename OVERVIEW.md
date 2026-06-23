# SDPP — Plain-English Overview

> A friendly, no-jargon guide to what this project is and how it works.
> For the technical deep-dives, see [`README.md`](README.md) and [`docs/`](docs/).

---

## What is this, in one sentence?

SDPP (**Secure Data Protection Platform**) is a **digital high-security vault** —
software that takes sensitive files (evidence, documents, recordings) and locks
them up so that even if someone steals the hard drive or the database, all they
get is scrambled, unreadable junk.

---

## The one idea behind everything: encryption

**Encryption** just means scrambling data with a secret key so it's unreadable,
then unscrambling it later with that same key. **No key = no reading it.** That's
the foundation the whole system is built on.

---

## The "safe-deposit box" picture

This is the easiest way to understand how it protects your files:

- 🗂️ **Every file gets its own unique lock and key.** Two files never share a key.
  (In the code this per-file key is called a **DEK** — Data Encryption Key.)
- 🔐 **All those little keys are themselves locked inside one master safe.** The
  master safe's key (the **Master Key**) is the crown jewel — it lives somewhere
  separate and protected, and is **never stored in the database**.
- 📦 So the database only ever holds **scrambled files + locked-up keys**. Stealing
  it is like stealing a pile of locked boxes and a pile of locked key-cases —
  useless without the master key.

This pattern is called **envelope encryption**, and it's exactly how big cloud
providers (AWS, Google, etc.) protect data.

---

## The main parts (what each one does)

| Part | In plain English |
|------|------------------|
| 🚪 **Login** (Authentication) | Checks who you are. Passwords are stored scrambled, so even the system can't read them. |
| 🪪 **Roles** (Authorization) | Different "badges" give different access. An `admin` can do everything; a `viewer` can only look. Trying to do something your badge doesn't allow = politely denied. |
| 🔒 **Encryption / Vault** | Scrambles files on upload, unscrambles on download. Each file gets its own key (see the safe-deposit box above). |
| 🛡️ **Integrity check** | Takes a unique "fingerprint" of each file when stored. Before letting you download it, it re-checks the fingerprint — if even one byte was tampered with, it **blocks access and raises an alarm**. |
| 🧾 **Audit log** | A tamper-proof logbook. Every action (login, upload, download, delete) is recorded so it **can't be secretly edited or erased** — and the system can prove it wasn't. |
| 🔑 **Key management** | Creates, rotates (swaps out), and destroys the keys safely. |
| 📊 **Dashboard** | The home screen showing health score, alerts, storage, and recent activity. |
| 📋 **Compliance** | Generates reports proving the system follows recognized security standards (OWASP, NIST, ISO 27001). |

---

## What actually happens when you use it

1. **You log in** → the system gives your browser a temporary pass (a "token").
2. **You upload a file** → it instantly scrambles the file with a brand-new key,
   locks that key in the master safe, takes a fingerprint, writes it in the
   logbook, and stores **only** the scrambled version.
3. **You download it** → it checks the fingerprint (untampered?), unlocks the key,
   unscrambles the file, hands you the original, and logs that too.
4. If anyone **tampered** with the stored file in between, step 3 stops cold and
   flags a security alert. The file gets quarantined.

---

## How to run it (locally)

The app has two halves that run together:

- **Backend** (the brains + vault) → http://127.0.0.1:8000 (API docs at `/docs`)
- **Frontend** (the website you click) → **http://localhost:5173**

Open **http://localhost:5173** in your browser and log in.

### Logins you can use
| Username | Password | What they can do |
|----------|----------|------------------|
| `admin` | `Admin-Demo-P@ssw0rd!` | Everything |
| `officer` | `Demo-Sdpp-P@ss1!` | Manage keys, alerts, audit, compliance |
| `analyst` | `Demo-Sdpp-P@ss1!` | Upload/download/verify files |
| `auditor` | `Demo-Sdpp-P@ss1!` | Read-only: audit & reports |
| `viewer` | `Demo-Sdpp-P@ss1!` | Dashboard + file list only |

*(Try logging in as `viewer` then `admin` to see how the available actions change —
that's the role system in action.)*

---

## Where things live (folder map)

```
SDPP/
├── backend/      The brains: encryption, login, vault, audit, API
│   └── app/      (core security code is in app/core/security/)
├── frontend/     The website you click (React)
├── docs/         Documentation (see below)
├── nginx/        Web-server config for secure HTTPS in production
└── docker-compose.yml   One command to run the whole thing for real
```

## What the documents in `docs/` are for

| File | What it's for |
|------|---------------|
| `ARCHITECTURE.md` | Diagrams of how the pieces fit together |
| `SECURITY.md` | The detailed encryption design |
| `THREAT_MODEL.md` | "What could go wrong and how we stop it" |
| `RISK_ASSESSMENT.md` | A scored list of risks |
| `COMPLIANCE.md` | How it maps to security standards |
| `PENTEST.md` | A checklist for security testers (how to attack it & confirm defenses) — *not something you need to act on* |
| `DEPLOYMENT.md` | How to put it live on a server |
| `PRODUCTION_READINESS.md` | A go-live checklist |

---

## Honest status

- ✅ **It's real and works** — you can log in, upload/encrypt files, download/decrypt
  them, see the dashboard, and generate compliance reports right now.
- ✅ **It's tested** — 193 automated tests pass, including attack simulations.
- 🟡 **For a real production launch**, the remaining work is mostly *organizational*,
  not code: an independent security audit, a real hardware key store (HSM/cloud KMS),
  and a proper TLS certificate. See `docs/PRODUCTION_READINESS.md`.

---

## The simplest possible summary

You give it a file → it locks the file in its own box → locks the box's key in a
master safe → and writes everything in a logbook that can't be faked. Later, only
the right person, with the right badge, can get the original file back — and if
anyone messed with it in the meantime, the system knows.
