# PHASE 2.1 — Web Dashboard Breakdown

**Target:** React + Vite + Tailwind frontend sesuai `mockups/dashboard.png`,
memakai REST API yang sudah ada (S8). Tidak ada perubahan backend kecuali
CORS untuk dev.

**Stack:** React 18 + Vite 5 + Tailwind 3 + fetch (no state lib — 3 halaman
tidak butuh store). Dev proxy Vite → uvicorn :8000. Build output
`web/dist/` di-serve uvicorn sebagai static files untuk produksi.

**Prinsip:** setiap sub-step ships complete + verified, STOP untuk approval.

---

## P2.1a — Scaffold + Lookup Page (core) 

**Deliverable:**
- `web/` scaffold (Vite + React + Tailwind), dev proxy `/api` → :8000
- Komponen: `SearchBar` (input IOC + lang dropdown EN/DE/ID + tombol Analyze),
  `VerdictCard` (verdict ber-warna, confidence, score bar, action badge,
  explanation, tags), `SourceCards` (grid per analyzer: VT/AbuseIPDB/OTX/
  WHOIS dengan format per sumber + live/cached badge), `ReportPanel`
  (markdown report + tombol copy)
- Auto-detect hint: saat mengetik, tampilkan tipe IOC terdeteksi
  (duplikasi ringan logika normalizer di JS — regex sederhana)
- State kosong ("paste an IOC…"), loading (spinner per analyzer selesai),
  error (invalid IOC → pesan jelas)
- Dark theme sesuai mockup (#0b0f14 bg, cyan accent)

**Verify:**
- `npm run build` sukses
- dev server jalan, lookup `google.com` (no key needed) menampilkan verdict
  card + WHOIS card live
- screenshot hasil render dikirim untuk review

---

## P2.1b — History Page

**Deliverable:**
- Route `/history`: tabel lookup (waktu, IOC, tipe, score, verdict ber-warna,
  lang), paginasi (limit/offset via API), klik baris → drawer/modal detail
  berisi full LookupResult (verdict card + sumber + report, reuse komponen P2.1a)
- Tombol refresh, empty state

**Verify:** setelah 3 lookup via CLI, semua muncul di halaman History web;
klik salah satu membuka detail yang identik dengan hasil lookup.

---

## P2.1c — Status Bar + Health Integration

**Deliverable:**
- Sidebar ala mockup: logo, nav (Lookup/History), status live per analyzer
  + AI (poll `GET /api/v1/health` tiap 30s) — dot hijau/merah
- Banner peringatan kalau AI unreachable ("AI down — heuristic verdicts only")

**Verify:** matikan provider AI (atau blokir network) → banner muncul tanpa
reload; analyzer tanpa key tampil merah.

---

## P2.1d — Production Serving + Polish

**Deliverable:**
- FastAPI serve `web/dist/` di `/` (SPA fallback ke index.html)
- Satu perintah jalan: `uvicorn ioc_insight.api:app` → UI + API satu port
- README update (screenshot, cara run dev vs prod)
- Cloudflare quick tunnel notes (akses dari HP — pola yang sudah Anda pakai)

**Verify:** `npm run build` → uvicorn → buka `http://localhost:8000` dari
browser, full flow lookup → history → copy report berfungsi; screenshot final.

---

## Estimasi & dependencies

| Step | File utama | Tergantung pada |
|---|---|---|
| P2.1a | web/src/{App,components/*}.jsx, tailwind.config | API S8 (sudah ada) |
| P2.1b | pages/History.jsx, api.js | API history S9 (sudah ada) |
| P2.1c | components/Sidebar.jsx | API health S8 (sudah ada) |
| P2.1d | api.py (static mount), README | a–c selesai |

**Open decision:**
- D-5: bahasa default UI — ikut `config.yaml` (`defaults.lang`) atau selector
  per-lookup saja? (rekomendasi: selector per-lookup, default dari config)
