# SDPP Frontend

React + TypeScript + Vite + Tailwind CSS, with Shadcn-style UI primitives
(`src/components/ui`). Implements the security operations console:

- **Login** — JWT auth with automatic refresh-token rotation.
- **Dashboard** — encryption health score, encrypted-file count, integrity
  violations, failed decryptions, key rotations, storage usage, alerts, recent events.
- **File Vault** — upload (client → encrypted at rest), download (decrypt),
  integrity verification, and crypto-shred deletion.
- **Audit Trail** — immutable hash-chained events with on-demand chain verification.
- **Compliance** — generate & view OWASP ASVS / NIST / ISO 27001 scored reports.

## Develop
```bash
npm install
npm run dev          # http://localhost:5173 (proxies /api → http://localhost:8000)
```

## Build / typecheck
```bash
npm run typecheck    # tsc --noEmit
npm run build        # type-check + production bundle to dist/
```

## Design notes
- **No tokens in JS-accessible storage in production:** for this reference build,
  tokens are kept in `localStorage` for simplicity; for higher assurance, switch to
  HttpOnly cookies + CSRF protection (the backend already supports secure cookies).
- The strict backend/nginx **CSP** (`script-src 'self'`) means no inline scripts.
- Add more Shadcn components with `npx shadcn@latest add <component>`.
