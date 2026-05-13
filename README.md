# URFU Schedule Telegram Bot

Telegram bot for URFU schedule with:
- day/week viewing,
- reminders,
- Modeus session support,
- iPhone calendar export (`.ics`).

## 1) Requirements

- Linux server (Ubuntu 22.04+ recommended)
- Python 3.12+
- `git`

## 2) Clone and Setup

```bash
git clone <your-repo-url> /opt/urfu-schedule-bot
cd /opt/urfu-schedule-bot

python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

Install Playwright browser runtime (required for Modeus auth flow):

```bash
.venv/bin/playwright install chromium
```

## 3) Environment Variables

Create `.env` from template:

```bash
cp .env.example .env
```

Required:
- `BOT_TOKEN` - Telegram bot token
- `PASSWORD_ENCRYPTION_KEY` - long random string for password encryption at rest

Optional:
- `DATABASE_PATH` (default: `bot.db`)
- `MORNING_HOUR` (default: `7`)
- `MORNING_MINUTE` (default: `0`)
- `CALENDAR_LINK_BASE_URL`, `CALENDAR_LINK_HOST`, `CALENDAR_LINK_PORT` (for public iPhone calendar links)

Generate a strong encryption key, for example:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

## 4) Run Manually

```bash
cd /opt/urfu-schedule-bot
source .venv/bin/activate
set -a
source .env
set +a
python main.py
```

## 5) Run as systemd Service

Copy provided unit file:

```bash
sudo cp deploy/urfu-schedule-bot.service /etc/systemd/system/urfu-schedule-bot.service
```

Edit `User`, `Group`, `WorkingDirectory`, `EnvironmentFile`, and `ExecStart` if your paths differ.

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable urfu-schedule-bot
sudo systemctl start urfu-schedule-bot
sudo systemctl status urfu-schedule-bot
```

Logs:

```bash
journalctl -u urfu-schedule-bot -f
```

## 6) Update on Server

```bash
cd /opt/urfu-schedule-bot
git pull
.venv/bin/pip install -r requirements.txt
sudo systemctl restart urfu-schedule-bot
```

## Notes

- The bot behavior/feature set is unchanged by this deployment prep.
- Keep `.env` out of git.
- If `PASSWORD_ENCRYPTION_KEY` changes, previously encrypted stored passwords cannot be decrypted.
- `.env` is loaded automatically on startup (`python-dotenv`).
