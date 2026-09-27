# CyberShield AI

A defensive web security assessment MVP for websites owned by the signed-in user or explicitly authorized for testing. It performs bounded, non-destructive HTTP checks, stores per-user scan history, explains findings, and generates PDF reports.

## Features

- Django authentication with registration, login, and logout
- Authorization-gated scans, per-user data isolation, and REST endpoints
- Safe checks for HTTPS behavior, common security headers, cookie flags, CORS, allowed HTTP methods, and public technology disclosure
- Public-address-only target validation, pinned connections, same-host redirect handling, strict timeouts, bounded response reads, and rate limiting
- Transparent finding-weight score from 0 to 100
- Local beginner-friendly AI analysis with optional environment-configured OpenAI-compatible provider
- Demo dataset, dashboard charts, audit records, scan history, and PDF download
- SQLite for the out-of-box demo and PostgreSQL support through `DATABASE_URL`

## Score methodology

The score starts at 100 and subtracts 25 for each Critical finding, 15 for each High, 8 for each Medium, and 3 for each Low. Informational findings carry no score penalty. The result is clamped to 0–100. A finding represents an observed configuration concern, not proof of exploitation.

## Requirements

Python 3.10 or newer. PostgreSQL is optional for local demo use.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open `http://127.0.0.1:8000/`. Register a regular account or use the superuser. The project uses SQLite unless `DATABASE_URL` is configured. For a production-style deployment, run `python manage.py collectstatic --noinput` and start the WSGI application with `gunicorn config.wsgi:application --bind 0.0.0.0:8000` behind an HTTPS reverse proxy.

## Environment

Set a unique `DJANGO_SECRET_KEY` and `DJANGO_DEBUG=False` in any non-demo deployment. Production mode also requires a non-console email backend and an SMTP host so password-reset links are not sent to server logs. For an HTTPS deployment, set `DJANGO_SECURE_COOKIES=True`, `DJANGO_SSL_REDIRECT=True`, and configure `CSRF_TRUSTED_ORIGINS` for the exact site origin. Set `DATABASE_URL` to a PostgreSQL connection string to use PostgreSQL. AI provider access is optional and disabled unless both `AI_API_URL` and `AI_API_KEY` are configured; keys are never rendered in the interface.

## Scanner safeguards

The scanner is intended only for authorized defensive assessment. It requires an explicit authorization confirmation, rejects non-public IP destinations and non-HTTP(S) URLs, permits only default HTTP/HTTPS ports, limits redirects to the same hostname, limits response reads and request duration, allows at most five real scans per user per rolling hour, and sends only GET and OPTIONS requests. It does not crawl, exploit, authenticate to targets, or test destructive methods. DNS and network-level protections should also be applied at deployment time. Never expose the scanning endpoints to anonymous users.

## API

Session-authenticated DRF endpoints are under `/api/`: create/list scans, view scan results, list and inspect vulnerabilities, request AI explanation, list reports, and create/download reports. API scan creation requires `authorized: true`.

## Demo

Use **View demo** on the landing page or **Load demo scan** on the dashboard. Demo data is labeled and is never produced by contacting a real target.

## Limitations

This MVP is a configuration checker, not a penetration-testing suite or compliance certification. Findings are heuristic; manually verify before making operational decisions. Certificate checks rely on the Python TLS trust store. Generated PDFs are written outside `MEDIA_ROOT` and served only through authenticated ownership-checked endpoints. Production deployment requires persistent private report storage, HTTPS, secure session/cookie settings, a hardened database, outbound egress controls, backups, monitoring, and a formal authorization process.

### Optional scoring and email configuration

The default score penalties can be changed with `SCORE_PENALTY_CRITICAL`, `SCORE_PENALTY_HIGH`, `SCORE_PENALTY_MEDIUM`, and `SCORE_PENALTY_LOW`. Informational observations carry no penalty. Reports and workspace settings display the active weights. Local password-reset messages use Django's console email backend. Configure `EMAIL_BACKEND`, `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS`, and `DEFAULT_FROM_EMAIL` for an authenticated production SMTP provider; secrets belong only in server environment variables.
