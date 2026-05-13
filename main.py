import asyncio
import base64
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, time, timezone
from typing import Optional, List, Any
from urllib.parse import parse_qs, urlparse, unquote
from zoneinfo import ZoneInfo


import aiosqlite
from aiohttp import ClientSession, ClientTimeout
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import Message, CallbackQuery, BufferedInputFile, ReplyKeyboardMarkup, KeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()

_FALLBACK_COOKIES: Optional[dict[str, Any]] = None
_FALLBACK_HEADERS: Optional[dict[str, Any]] = None


def get_fallback_auth() -> tuple[dict[str, Any], dict[str, Any]]:
    global _FALLBACK_COOKIES, _FALLBACK_HEADERS
    if _FALLBACK_COOKIES is None or _FALLBACK_HEADERS is None:
        from constants import COOKIES, HEADERS

        _FALLBACK_COOKIES = COOKIES
        _FALLBACK_HEADERS = HEADERS
    return _FALLBACK_COOKIES, _FALLBACK_HEADERS

# ==============================
# CONFIG
# ==============================
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
DATABASE_PATH = os.getenv("DATABASE_PATH", "bot.db").strip() or "bot.db"
TIMEZONE = ZoneInfo("Asia/Yekaterinburg")
MORNING_HOUR = int(os.getenv("MORNING_HOUR", "7"))
MORNING_MINUTE = int(os.getenv("MORNING_MINUTE", "0"))

#
# IMPORTANT:
# 1) Replace BASE_LOGIN_URL and BASE_SCHEDULE_URL with real UrFU endpoints.
# 2) Replace parse_* functions with your actual parser.
# 3) Prefer storing auth cookies/tokens instead of raw password in production.
#
BASE_LOGIN_URL = "https://example.urfu.ru/login"
BASE_SCHEDULE_URL = "https://istudent.urfu.ru/s/schedule/schedule"
MODEUS_SCHEDULE_URL = (
    "https://urfu.modeus.org/schedule-calendar/my"
    "?timeZone=%22Asia%2FYekaterinburg%22"
    "&calendar=%7B%22view%22:%22agendaWeek%22,%22date%22:%222025-09-29%22%7D"
    "&grid=%22Grid.07%22"
)
MODEUS_EVENTS_URL = "https://urfu.modeus.org/schedule-calendar-v2/api/calendar/events/search"
MODEUS_PROXY_URL = (
    os.getenv("MODEUS_PROXY_URL")
    or os.getenv("HTTPS_PROXY")
    or os.getenv("HTTP_PROXY")
    or ""
).strip()
PLAYWRIGHT_PROXY_URL = (os.getenv("PLAYWRIGHT_PROXY_URL") or MODEUS_PROXY_URL).strip()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

router = Router()


WELCOME_TEXT = (
    "Привет! Я бот с расписанием УрФУ.\n\n"
    "Сначала авторизуйся один раз через кнопку 🔐, чтобы я мог получать твое расписание.\n\n"
    "Выбирай нужный вариант внизу:\n"
    "• 📅 Сегодня\n"
    "• 🗓 Выбрать неделю\n"
    "• ⏰ Напоминания\n"
    "• 🔐 Авторизация"
)


# ==============================
# DATABASE
# ==============================
CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    telegram_id INTEGER PRIMARY KEY,
    urfu_login TEXT NOT NULL,
    urfu_password TEXT NOT NULL,
    modeus_access_token TEXT,
    modeus_person_id TEXT,
    modeus_token_exp INTEGER,
    notifications_enabled INTEGER NOT NULL DEFAULT 1,
    pair_reminders_enabled INTEGER NOT NULL DEFAULT 1,
    pair_reminder_days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

PASSWORD_PLACEHOLDER = "__NOT_STORED__"
_PASSWORD_CIPHER: Optional[Fernet] = None

CREATE_SENT_LOG_SQL = """
CREATE TABLE IF NOT EXISTS sent_daily_notifications (
    telegram_id INTEGER NOT NULL,
    sent_date TEXT NOT NULL,
    PRIMARY KEY (telegram_id, sent_date)
);
"""

CREATE_PAIR_REMINDER_LOG_SQL = """
CREATE TABLE IF NOT EXISTS sent_pair_reminders (
    telegram_id INTEGER NOT NULL,
    reminder_key TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    PRIMARY KEY (telegram_id, reminder_key)
);
"""


async def init_db() -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(CREATE_USERS_SQL)
        await db.execute(CREATE_SENT_LOG_SQL)
        await db.execute(CREATE_PAIR_REMINDER_LOG_SQL)
        await ensure_users_columns(db)
        await db.commit()


async def ensure_users_columns(db: aiosqlite.Connection) -> None:
    cursor = await db.execute("PRAGMA table_info(users)")
    rows = await cursor.fetchall()
    existing = {row[1] for row in rows}
    required = {
        "modeus_access_token": "TEXT",
        "modeus_person_id": "TEXT",
        "modeus_token_exp": "INTEGER",
        "pair_reminders_enabled": "INTEGER NOT NULL DEFAULT 1",
        "pair_reminder_days": "TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6'",
    }
    for column, col_type in required.items():
        if column not in existing:
            await db.execute(f"ALTER TABLE users ADD COLUMN {column} {col_type}")
    await db.execute(
        "UPDATE users SET pair_reminder_days = '0,1,2,3,4,5,6' "
        "WHERE pair_reminder_days IS NULL OR TRIM(pair_reminder_days) = ''"
    )
    # Privacy policy: do not retain real passwords at rest.
    await db.execute(
        "UPDATE users SET urfu_password = ? WHERE urfu_password IS NULL OR TRIM(urfu_password) = ''",
        (PASSWORD_PLACEHOLDER,),
    )


def get_password_cipher() -> Fernet:
    global _PASSWORD_CIPHER
    if _PASSWORD_CIPHER is not None:
        return _PASSWORD_CIPHER
    secret = (os.getenv("PASSWORD_ENCRYPTION_KEY") or "").strip()
    if not secret:
        raise RuntimeError("Set PASSWORD_ENCRYPTION_KEY in environment")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    _PASSWORD_CIPHER = Fernet(key)
    return _PASSWORD_CIPHER


def encrypt_password(password: str) -> str:
    return get_password_cipher().encrypt(password.encode("utf-8")).decode("utf-8")


def decrypt_password(encrypted_password: Optional[str]) -> Optional[str]:
    raw = (encrypted_password or "").strip()
    if not raw or raw == PASSWORD_PLACEHOLDER:
        return None
    try:
        return get_password_cipher().decrypt(raw.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.warning("Stored password decrypt failed: invalid token format")
        return None
    except Exception:
        logger.exception("Stored password decrypt failed")
        return None


async def upsert_user_credentials(telegram_id: int, login: str, password: str) -> None:
    now = datetime.now(TIMEZONE).isoformat()
    encrypted_password = encrypt_password(password)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """
            INSERT INTO users (telegram_id, urfu_login, urfu_password, notifications_enabled, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                urfu_login = excluded.urfu_login,
                urfu_password = excluded.urfu_password,
                modeus_access_token = NULL,
                modeus_person_id = NULL,
                modeus_token_exp = NULL,
                updated_at = excluded.updated_at
            """,
            (telegram_id, login, encrypted_password, now, now),
        )
        await db.commit()


async def get_user(telegram_id: int) -> Optional[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM users WHERE telegram_id = ?",
            (telegram_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def save_modeus_session(
    telegram_id: int,
    access_token: str,
    person_id: str,
    token_exp: int,
) -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """
            UPDATE users
            SET modeus_access_token = ?,
                modeus_person_id = ?,
                modeus_token_exp = ?,
                updated_at = ?
            WHERE telegram_id = ?
            """,
            (
                access_token,
                person_id,
                token_exp,
                datetime.now(TIMEZONE).isoformat(),
                telegram_id,
            ),
        )
        await db.commit()


def get_persisted_modeus_session(user: dict) -> Optional[dict[str, Any]]:
    token = user.get("modeus_access_token")
    person_id = user.get("modeus_person_id")
    token_exp = user.get("modeus_token_exp")
    if not token or not person_id or not token_exp:
        return None
    return {
        "access_token": token,
        "person_id": person_id,
        "token_exp": int(token_exp),
    }


def is_user_authorized(user: Optional[dict]) -> bool:
    if not user:
        return False
    if not (user.get("urfu_login") and user.get("modeus_access_token") and user.get("modeus_token_exp")):
        return False
    try:
        return int(user["modeus_token_exp"]) > int(datetime.now(timezone.utc).timestamp())
    except Exception:
        return False


def get_reminder_days(user: Optional[dict]) -> set[int]:
    if not user:
        return {0, 1, 2, 3, 4, 5, 6}
    raw = user.get("pair_reminder_days") or "0,1,2,3,4,5,6"
    result: set[int] = set()
    for part in str(raw).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            value = int(part)
            if 0 <= value <= 6:
                result.add(value)
        except ValueError:
            continue
    return result or {0, 1, 2, 3, 4, 5, 6}


async def get_all_enabled_users() -> List[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM users WHERE notifications_enabled = 1"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_all_pair_reminder_users() -> List[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM users WHERE pair_reminders_enabled = 1"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def set_notifications_enabled(telegram_id: int, enabled: bool) -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE users SET notifications_enabled = ?, updated_at = ? WHERE telegram_id = ?",
            (1 if enabled else 0, datetime.now(TIMEZONE).isoformat(), telegram_id),
        )
        await db.commit()


async def set_pair_reminders_enabled(telegram_id: int, enabled: bool) -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE users SET pair_reminders_enabled = ?, updated_at = ? WHERE telegram_id = ?",
            (1 if enabled else 0, datetime.now(TIMEZONE).isoformat(), telegram_id),
        )
        await db.commit()


async def set_pair_reminder_days(telegram_id: int, days: set[int]) -> None:
    days_str = ",".join(str(x) for x in sorted(days))
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE users SET pair_reminder_days = ?, updated_at = ? WHERE telegram_id = ?",
            (days_str, datetime.now(TIMEZONE).isoformat(), telegram_id),
        )
        await db.commit()


async def was_daily_notification_sent(telegram_id: int, sent_date: str) -> bool:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "SELECT 1 FROM sent_daily_notifications WHERE telegram_id = ? AND sent_date = ?",
            (telegram_id, sent_date),
        )
        row = await cursor.fetchone()
        return row is not None


async def was_pair_reminder_sent(telegram_id: int, reminder_key: str) -> bool:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "SELECT 1 FROM sent_pair_reminders WHERE telegram_id = ? AND reminder_key = ?",
            (telegram_id, reminder_key),
        )
        return await cursor.fetchone() is not None


async def mark_daily_notification_sent(telegram_id: int, sent_date: str) -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO sent_daily_notifications (telegram_id, sent_date) VALUES (?, ?)",
            (telegram_id, sent_date),
        )
        await db.commit()


async def mark_pair_reminder_sent(telegram_id: int, reminder_key: str) -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO sent_pair_reminders (telegram_id, reminder_key, sent_at) VALUES (?, ?, ?)",
            (telegram_id, reminder_key, datetime.now(TIMEZONE).isoformat()),
        )
        await db.commit()


# ==============================
# FSM
# ==============================
class AuthStates(StatesGroup):
    waiting_login = State()
    waiting_password = State()


# ==============================
# DATA MODELS
# ==============================
@dataclass
class Lesson:
    time_range: str
    subject: str
    teacher: str
    room: str
    lesson_type: str


# ==============================
# URFU CLIENT (TEMPLATE)
# ==============================
class UrfuScheduleClient:
    """
    Template client.
    Replace auth and parsing logic with actual UrFU endpoints/selectors.
    """

    _modeus_token_cache: dict[str, dict[str, Any]] = {}
    _modeus_auth_lock: Optional[asyncio.Lock] = None

    def __init__(self) -> None:
        self.session: Optional[ClientSession] = None
        self.last_modeus_session: Optional[dict[str, Any]] = None
        self.proxy_url: Optional[str] = MODEUS_PROXY_URL or None

    async def __aenter__(self):
        self.session = ClientSession(timeout=ClientTimeout(total=45), trust_env=True)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def login(self, login: str, password: str) -> bool:
        if self.session is None:
            raise RuntimeError("Session is not initialized")

        # TEMPLATE:
        # resp = await self.session.post(BASE_LOGIN_URL, data={"login": login, "password": password})
        # html = await resp.text()
        # return resp.status == 200 and "logout" in html.lower()

        if not login or not password:
            return False
        return True

    async def fetch_week_schedule(
        self,
        login: str,
        password: Optional[str],
        week_offset: int = 0,
        persisted_modeus_session: Optional[dict[str, Any]] = None,
    ) -> dict:
        if self.session is None:
            raise RuntimeError("Session is not initialized")

        logger.info("Fetch week schedule requested: week_offset=%s", week_offset)
        try:
            logger.info("Trying Modeus API flow")
            return await self.fetch_modeus_week_schedule(
                login,
                password,
                week_offset,
                persisted_modeus_session=persisted_modeus_session,
            )
        except Exception:
            # Security-first behavior: do not fallback to shared legacy cookies,
            # otherwise there is a risk of returning schedule from a foreign session.
            logger.exception("Modeus API failed")
            raise


    async def fetch_today_schedule(
        self,
        login: str,
        password: Optional[str],
        persisted_modeus_session: Optional[dict[str, Any]] = None,
    ) -> dict:
        all_week = await self.fetch_week_schedule(
            login,
            password,
            week_offset=0,
            persisted_modeus_session=persisted_modeus_session,
        )

        today = datetime.now(TIMEZONE).date()
        today_lessons = {
            "online": [],
            "offline": [],
        }

        for lesson in all_week["offline"]:
            lesson_date = parse_russian_date(lesson["date"]).date()
            if lesson_date == today:
                today_lessons["offline"].append(lesson)

        for lesson in all_week["online"]:
            lesson_date_raw = lesson.get("date")
            if not lesson_date_raw:
                continue
            lesson_date = parse_russian_date(lesson_date_raw).date()
            if lesson_date == today:
                today_lessons["online"].append(lesson)

        return today_lessons

    def _week_range(self, week_offset: int = 0):
        now = datetime.now(TIMEZONE).date()
        monday = now - timedelta(days=now.weekday()) + timedelta(weeks=week_offset)
        sunday = monday + timedelta(days=6)
        return monday, sunday

    async def fetch_modeus_week_schedule(
        self,
        login: str,
        password: Optional[str],
        week_offset: int,
        persisted_modeus_session: Optional[dict[str, Any]] = None,
    ) -> dict:
        if self.session is None:
            raise RuntimeError("Session is not initialized")
        if not login:
            raise ValueError("Нужен логин УрФУ для доступа к Modeus")

        token, person_id, exp = await self._ensure_modeus_auth(
            login,
            password,
            preferred_session=persisted_modeus_session,
        )
        time_min, time_max = self._modeus_week_range_utc(week_offset)
        logger.info(
            "Modeus events request: person_id=%s week_offset=%s timeMin=%s timeMax=%s",
            person_id,
            week_offset,
            time_min,
            time_max,
        )
        body = {
            "size": 500,
            "timeMin": time_min,
            "timeMax": time_max,
            "attendeePersonId": [person_id],
        }

        async def _request_events(bearer_token: str):
            headers = {
                "Authorization": f"Bearer {bearer_token}",
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "Referer": MODEUS_SCHEDULE_URL,
                "Accept-Language": "ru-RU",
            }
            return await self.session.post(
                MODEUS_EVENTS_URL,
                params={"tz": "Asia/Yekaterinburg"},
                headers=headers,
                json=body,
                proxy=self.proxy_url,
            )

        resp = await _request_events(token)
        if resp.status == 401:
            logger.warning("Modeus token rejected with 401, refreshing token")
            if not password:
                raise ValueError("Сессия истекла. Нажми «🔐 Авторизоваться» и введи пароль заново.")
            token, person_id, exp = await self._ensure_modeus_auth(login, password, force_refresh=True)
            body["attendeePersonId"] = [person_id]
            resp = await _request_events(token)

        if resp.status != 200:
            raise ValueError(f"Modeus вернул статус {resp.status}")

        payload = await resp.json(content_type=None)
        logger.info("Modeus events response received successfully")
        self.last_modeus_session = {
            "access_token": token,
            "person_id": person_id,
            "token_exp": exp,
        }
        return self.parse_modeus_schedule_json(payload)

    async def _ensure_modeus_auth(
        self,
        login: str,
        password: Optional[str],
        force_refresh: bool = False,
        preferred_session: Optional[dict[str, Any]] = None,
    ) -> tuple[str, str, int]:
        cache_key = login.strip().lower()
        now_ts = datetime.now(timezone.utc).timestamp()
        if not force_refresh and preferred_session:
            token = preferred_session.get("access_token")
            person_id = preferred_session.get("person_id")
            exp = int(preferred_session.get("token_exp") or 0)
            if token and person_id and exp - 120 > now_ts and self._looks_like_jwt(token):
                logger.info("Using persisted Modeus session from DB for %s", cache_key)
                self._modeus_token_cache[cache_key] = {
                    "token": token,
                    "person_id": person_id,
                    "exp": exp,
                }
                return token, person_id, exp

        cached = self._modeus_token_cache.get(cache_key)
        if cached and not force_refresh and (cached["exp"] - 120 > now_ts):
            logger.info("Modeus token cache hit for user %s", cache_key)
            return cached["token"], cached["person_id"], cached["exp"]

        if self.__class__._modeus_auth_lock is None:
            self.__class__._modeus_auth_lock = asyncio.Lock()

        async with self.__class__._modeus_auth_lock:
            cached = self._modeus_token_cache.get(cache_key)
            if cached and not force_refresh and (cached["exp"] - 120 > now_ts):
                logger.info("Modeus token cache hit after lock for user %s", cache_key)
                return cached["token"], cached["person_id"], cached["exp"]

            if not password:
                raise ValueError("Сессия истекла. Для продолжения заново авторизуйся через «🔐 Авторизоваться».")
            logger.info("Refreshing Modeus token for user %s", cache_key)
            token = await asyncio.to_thread(self._login_modeus_and_capture_token, login, password)
            claims = self._decode_jwt_payload(token)
            person_id = claims.get("person_id") or claims.get("sub")
            exp = int(claims.get("exp", 0))
            if not person_id or not exp:
                raise ValueError("Не удалось прочитать person_id/exp из Modeus токена")

            self._modeus_token_cache[cache_key] = {
                "token": token,
                "person_id": person_id,
                "exp": exp,
            }
            return token, person_id, exp

    async def bootstrap_modeus_session(self, login: str, password: str) -> dict[str, Any]:
        token, person_id, exp = await self._ensure_modeus_auth(login, password, force_refresh=True)
        return {
            "access_token": token,
            "person_id": person_id,
            "token_exp": exp,
        }

    def _login_modeus_and_capture_token(self, login: str, password: str) -> str:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright

        captured_jwt_token: Optional[str] = None
        proxy_settings = self._build_playwright_proxy_settings()

        def capture_auth_header(request):
            nonlocal captured_jwt_token
            auth = request.headers.get("authorization")
            if auth and auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1]
                if self._looks_like_jwt(token):
                    captured_jwt_token = token

        with sync_playwright() as p:
            try:
                # Prefer system Chrome so we do not depend on downloaded Playwright binaries.
                browser = p.chromium.launch(
                    channel="chrome",
                    headless=True,
                    proxy=proxy_settings,
                )
            except PlaywrightError:
                # Fallback to bundled chromium if it is available.
                browser = p.chromium.launch(
                    headless=True,
                    proxy=proxy_settings,
                )
            context = browser.new_context()
            page = context.new_page()
            page.on("request", capture_auth_header)
            try:
                page.goto(MODEUS_SCHEDULE_URL, wait_until="load", timeout=90000)
                logger.info("Modeus auth open URL: %s", page.url)

                if "sso.urfu.ru" not in page.url:
                    try:
                        page.wait_for_url("**sso.urfu.ru/**", timeout=30000)
                        logger.info("Modeus auth redirected to SSO: %s", page.url)
                    except PlaywrightTimeoutError:
                        logger.info("SSO redirect not observed in 30s, current URL: %s", page.url)

                if "sso.urfu.ru" in page.url:
                    page.get_by_role("textbox", name="Учетная запись пользователя").fill(login)
                    page.get_by_role("textbox", name="Пароль").fill(password)
                    page.get_by_role("button", name="Вход").click()
                    logger.info("Credentials submitted to SSO")
                    page.wait_for_timeout(2500)
                    if "sso.urfu.ru" in page.url:
                        if page.get_by_text("Неверный идентификатор пользователя или пароль").count() > 0:
                            raise ValueError("Неверный логин или пароль УрФУ")
                    logger.info("Still on SSO after submit, waiting for redirect")

                page.wait_for_url("**urfu.modeus.org/schedule-calendar/my**", timeout=90000)
                logger.info("Returned to Modeus after SSO")
                page.wait_for_timeout(4000)
            except PlaywrightTimeoutError as exc:
                raise ValueError("Таймаут авторизации в Modeus") from exc
            finally:
                current_url = page.url
                browser.close()

        fragment = parse_qs(urlparse(current_url).fragment)
        fragment_access_token = fragment.get("access_token", [None])[0]
        fragment_id_token = fragment.get("id_token", [None])[0]

        captured_token = (
            captured_jwt_token
            or (fragment_id_token if self._looks_like_jwt(fragment_id_token) else None)
            or (fragment_access_token if self._looks_like_jwt(fragment_access_token) else None)
        )
        if captured_token:
            logger.info("Modeus token captured successfully")
            return captured_token

        if fragment_access_token:
            logger.error("Modeus access_token exists but is not JWT")
            raise ValueError("Modeus вернул access_token не в JWT-формате")

        if fragment_id_token:
            logger.error("Modeus id_token exists but is not JWT")
            raise ValueError("Modeus вернул id_token не в JWT-формате")

        if not captured_jwt_token:
            raise ValueError("Не удалось получить access token Modeus")
        return captured_jwt_token

    def _build_playwright_proxy_settings(self) -> Optional[dict[str, str]]:
        proxy = PLAYWRIGHT_PROXY_URL.strip()
        if not proxy:
            return None
        parsed = urlparse(proxy)
        if not parsed.scheme or not parsed.hostname:
            logger.warning("PLAYWRIGHT proxy URL is invalid: %s", proxy)
            return None
        settings: dict[str, str] = {
            "server": f"{parsed.scheme}://{parsed.hostname}{f':{parsed.port}' if parsed.port else ''}"
        }
        if parsed.username:
            settings["username"] = unquote(parsed.username)
        if parsed.password:
            settings["password"] = unquote(parsed.password)
        return settings

    def _decode_jwt_payload(self, token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) < 2:
            raise ValueError("Некорректный JWT токен")
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            payload_raw = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
            return json.loads(payload_raw)
        except Exception as exc:
            raise ValueError("Не удалось декодировать JWT payload") from exc

    def _looks_like_jwt(self, token: Optional[str]) -> bool:
        if not token:
            return False
        return token.count(".") == 2

    def _modeus_week_range_utc(self, week_offset: int) -> tuple[str, str]:
        monday, _ = self._week_range(week_offset)
        start_local = datetime.combine(monday, time(0, 0), tzinfo=TIMEZONE)
        end_local = start_local + timedelta(days=7)
        start_utc = start_local.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_utc = end_local.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return start_utc, end_utc

    def get_week_timestamp(self, offset=0):
        now = datetime.now()
        monday = now - timedelta(days=now.weekday())
        monday += timedelta(weeks=offset)

        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)

        return int(monday.timestamp())

    def parse_schedule_payload(self, payload: str) -> dict:
        payload = payload.strip()
        if payload.startswith("{"):
            try:
                parsed_json = json.loads(payload)
                return self.parse_schedule_json(parsed_json)
            except json.JSONDecodeError:
                logger.warning("Schedule response looks like JSON but decoding failed, fallback to HTML parser")

        return self.parse_schedule_html(payload)

    def parse_schedule_json(self, data: dict[str, Any]) -> dict:
        lessons_lists = {"online": [], "offline": []}
        events = data.get("_embedded", {}).get("events", [])

        for idx, event in enumerate(events, start=1):
            start_raw = event.get("start") or event.get("startsAt")
            end_raw = event.get("end") or event.get("endsAt")
            if not start_raw or not end_raw:
                continue

            try:
                start_dt = datetime.fromisoformat(start_raw)
                end_dt = datetime.fromisoformat(end_raw)
            except ValueError:
                continue

            date_label = f"{start_dt.day} {self._month_name_ru(start_dt.month)} {start_dt.year} г."
            date_week = self._weekday_short_ru(start_dt.weekday())
            type_lesson = self._normalize_lesson_type(event.get("typeId"))

            lesson_info = {
                "name": event.get("nameShort") or event.get("name") or "Без названия",
                "type": type_lesson,
                "place": "Не указано",
                "teacher": "Не указано",
                "time": f"{start_dt.strftime('%H:%M')} - {end_dt.strftime('%H:%M')}",
                "number_lesson": str(idx),
                "date": date_label,
                "date_week": date_week,
                "mode": "offline",
            }
            lessons_lists["offline"].append(lesson_info)

        return lessons_lists

    def parse_modeus_schedule_json(self, data: dict[str, Any]) -> dict:
        lessons_lists = {"online": [], "offline": []}
        embedded = data.get("_embedded", {})
        events = embedded.get("events", [])

        persons_by_href = {}
        for person in embedded.get("persons", []):
            href = (person.get("_links", {}).get("self", {}) or {}).get("href")
            if href:
                persons_by_href[href] = person.get("fullName", "Не указано")

        attendees_by_event = {}
        for attendee in embedded.get("event-attendees", []):
            if attendee.get("roleId") != "TEACH":
                continue
            event_href = (attendee.get("_links", {}).get("event", {}) or {}).get("href")
            person_href = (attendee.get("_links", {}).get("person", {}) or {}).get("href")
            if not event_href or not person_href:
                continue
            attendees_by_event.setdefault(event_href, []).append(persons_by_href.get(person_href, "Не указано"))

        event_locations_by_event_id = {
            location.get("eventId"): location
            for location in embedded.get("event-locations", [])
            if location.get("eventId")
        }
        event_rooms_by_href = {
            (item.get("_links", {}).get("self", {}) or {}).get("href"): item
            for item in embedded.get("event-rooms", [])
            if (item.get("_links", {}).get("self", {}) or {}).get("href")
        }
        rooms_by_href = {
            (room.get("_links", {}).get("self", {}) or {}).get("href"): room
            for room in embedded.get("rooms", [])
            if (room.get("_links", {}).get("self", {}) or {}).get("href")
        }
        course_name_by_href = {}
        for course_unit in embedded.get("course-unit-realizations", []):
            href = (course_unit.get("_links", {}).get("self", {}) or {}).get("href")
            if not href:
                continue
            course_name_by_href[href] = (
                course_unit.get("nameShort")
                or course_unit.get("name")
                or "Без названия"
            )

        cycle_course_name_by_href = {}
        lesson_team_cycle_ref_by_href = {}
        for cycle in embedded.get("cycle-realizations", []):
            cycle_href = (cycle.get("_links", {}).get("self", {}) or {}).get("href")
            course_href = (cycle.get("_links", {}).get("course-unit-realization", {}) or {}).get("href")
            course_name = (
                cycle.get("courseUnitRealizationNameShort")
                or course_name_by_href.get(course_href)
            )
            if cycle_href and course_name:
                cycle_course_name_by_href[cycle_href] = course_name
            cycle_id = cycle.get("id")
            if cycle_id and course_name:
                cycle_course_name_by_href[f"/{cycle_id}"] = course_name

        for lesson_team in embedded.get("lesson-realization-teams", []):
            team_href = (lesson_team.get("_links", {}).get("self", {}) or {}).get("href")
            cycle_id = lesson_team.get("cycleRealizationId")
            if team_href and cycle_id:
                lesson_team_cycle_ref_by_href[team_href] = f"/{cycle_id}"

        for event in events:
            start_raw = event.get("start")
            end_raw = event.get("end")
            if not start_raw or not end_raw:
                continue

            try:
                start_dt = datetime.fromisoformat(start_raw).astimezone(TIMEZONE)
                end_dt = datetime.fromisoformat(end_raw).astimezone(TIMEZONE)
            except ValueError:
                continue

            event_id = event.get("id")
            event_href = (event.get("_links", {}).get("self", {}) or {}).get("href")
            location = event_locations_by_event_id.get(event_id, {})

            place = location.get("customLocation") or "Не указано"
            event_room_href = (location.get("_links", {}).get("event-rooms", {}) or {}).get("href")
            if event_room_href:
                event_room = event_rooms_by_href.get(event_room_href, {})
                room_href = (event_room.get("_links", {}).get("room", {}) or {}).get("href")
                room = rooms_by_href.get(room_href, {})
                if room:
                    building_name = (room.get("building") or {}).get("nameShort") or (room.get("building") or {}).get("name")
                    room_name = room.get("nameShort") or room.get("name")
                    if building_name and room_name:
                        place = f"{building_name} / {room_name}"
                    elif room_name:
                        place = room_name

            teachers = attendees_by_event.get(event_href, [])
            teacher = ", ".join(sorted(set(teachers))) if teachers else "Не указано"
            lesson_type = self._normalize_lesson_type(event.get("typeId"))
            date_label = f"{start_dt.day} {self._month_name_ru(start_dt.month)} {start_dt.year} г."
            date_week = self._weekday_short_ru(start_dt.weekday())
            number_lesson = self._pair_number(start_dt.strftime("%H:%M"))
            event_name = self._resolve_modeus_event_name(
                event,
                course_name_by_href=course_name_by_href,
                cycle_course_name_by_href=cycle_course_name_by_href,
                lesson_team_cycle_ref_by_href=lesson_team_cycle_ref_by_href,
            )

            lesson = {
                "name": event_name,
                "type": lesson_type,
                "place": place,
                "teacher": teacher,
                "time": f"{start_dt.strftime('%H:%M')} - {end_dt.strftime('%H:%M')}",
                "number_lesson": number_lesson,
                "date": date_label,
                "date_week": date_week,
                "mode": "online" if is_online_place(place) else "offline",
            }

            if lesson["mode"] == "online":
                lessons_lists["online"].append(lesson)
            else:
                lessons_lists["offline"].append(lesson)

        return lessons_lists

    def _resolve_modeus_event_name(
        self,
        event: dict[str, Any],
        course_name_by_href: dict[str, str],
        cycle_course_name_by_href: dict[str, str],
        lesson_team_cycle_ref_by_href: dict[str, str],
    ) -> str:
        fallback_name = event.get("name") or event.get("nameShort") or "Без названия"
        links = event.get("_links", {})
        direct_course_href = (links.get("course-unit-realization", {}) or {}).get("href")
        if direct_course_href and course_name_by_href.get(direct_course_href):
            return course_name_by_href[direct_course_href]

        cycle_href = (links.get("cycle-realization", {}) or {}).get("href")
        if cycle_href and cycle_course_name_by_href.get(cycle_href):
            return cycle_course_name_by_href[cycle_href]

        team_href = (links.get("lesson-realization-team", {}) or {}).get("href")
        if team_href:
            cycle_ref = lesson_team_cycle_ref_by_href.get(team_href)
            if cycle_ref and cycle_course_name_by_href.get(cycle_ref):
                return cycle_course_name_by_href[cycle_ref]

        if not self._is_generic_modeus_event_name(fallback_name):
            return fallback_name

        return fallback_name

    def _is_generic_modeus_event_name(self, name: str) -> bool:
        normalized = (name or "").strip().lower()
        if not normalized:
            return True

        # Modeus often returns technical placeholders like "Практическое занятие 14".
        generic_patterns = (
            r"^лекция(\s+\d+)?$",
            r"^лекционное занятие(\s+\d+)?$",
            r"^практика(\s+\d+)?$",
            r"^практическое занятие(\s+\d+)?$",
            r"^семинар(\s+\d+)?$",
            r"^лабораторное занятие(\s+\d+)?$",
        )
        return any(re.match(pattern, normalized) for pattern in generic_patterns)

    def parse_schedule_html(self, html: str) -> dict:
        from bs4 import BeautifulSoup

        lessons_lists = {
            "online": [],
            "offline": [],
        }
        soup = BeautifulSoup(html, "html.parser")
        blocks = soup.find_all("div", class_="training-schedule")
        seen_dates = set()
        for block in blocks:
            date = block.find('div', class_='date').text.strip().replace('\u202f', ' ')
            date_week = block.find('div', class_='day-on-week').text.strip().replace('\u202f', ' ')

            if date_week in seen_dates:
                break

            seen_dates.add(date_week)

            lessons = block.find_all("tr", class_="inner-container")

            for lesson in lessons:
                el_lesson = lesson.find('td', class_='rasp')
                name_lesson = el_lesson.find('strong').text.strip()
                infos = [
                    " ".join(x.get_text(" ", strip=True).split())
                    for x in el_lesson.find_all('span', class_='info')
                ]

                type_lesson = "Не указано"
                place_lesson = "Не указано"
                teacher_lesson = "Не указано"

                for info in infos:
                    if "Преподаватель" in info:
                        teacher_lesson = info.replace("Преподаватель:", "").strip()

                    elif "Лекции" in info:
                        type_lesson = 'Лекция'
                    elif "Практические" in info:
                        type_lesson = 'Практика'
                    elif "Лабораторные" in info:
                        type_lesson = 'Лаба'

                    elif 'Х' in info or "Мира" in info or "Р" in info:
                        place_lesson = info

                    elif "https://" in info:
                        place_lesson = info

                time_lesson = lesson.find('td', class_='time').text.strip()

                number_lesson = lesson.find('td', class_='npair').text.strip()

                lesson_info = {
                    "name": name_lesson,
                    "type": type_lesson,
                    "place": place_lesson,
                    "teacher": teacher_lesson,
                    "time": time_lesson,
                    "number_lesson": number_lesson,
                    "date": date,
                    "date_week": date_week,
                    "mode": "online" if is_online_place(place_lesson) else "offline",
                }
                if lesson_info["mode"] == "online":
                    lessons_lists["online"].append(lesson_info)
                else:
                    lessons_lists["offline"].append(lesson_info)
            if block.find('td', class_='online-subject') != None:
                online_lessons = block.find_all('td', class_='online-subject')
                for on_lesson in online_lessons:
                    name_lesson = on_lesson.find('strong').text.strip()
                    infos = [
                        " ".join(x.get_text(" ", strip=True).split())
                        for x in on_lesson.find_all('span', class_='info')
                    ]
                    type_lesson = "Не указано"
                    place_lesson = "Не указано"
                    teacher_lesson = "Не указано"
                    dop_info = ""
                    for info in infos:
                        if "Преподаватель" in info:
                            teacher_lesson = info.replace("Преподаватель:", "").strip()

                        elif "Лекции" in info:
                            type_lesson = 'Лекция'
                        elif "Практические" in info:
                            type_lesson = 'Практика'
                        elif "Лабораторные" in info:
                            type_lesson = 'Лаба'

                        elif 'Х' in info or "Мира" in info or "Р" in info or "место проведения" in info:
                            place_lesson = info

                        elif "https://" in info:
                            place_lesson = info
                        else:
                            dop_info += info + '\n'
                    lesson_info = {
                        "name": name_lesson,
                        "type": type_lesson,
                        "place": place_lesson,
                        "teacher": teacher_lesson,
                        "time": "Онлайн",
                        "number_lesson": "•",
                        "date": date,
                        "date_week": date_week,
                        "mode": "online",
                    }
                    lessons_lists['online'].append(lesson_info)
        return lessons_lists

    def _normalize_lesson_type(self, type_code: Optional[str]) -> str:
        if not type_code:
            return "Не указано"
        mapping = {
            "LECT": "Лекция",
            "LAB": "Лаба",
            "SEMI": "Практика",
            "PRAC": "Практика",
            "MID_CHECK": "Аттестация",
            "CONS": "Консультация",
        }
        return mapping.get(type_code.upper(), type_code)

    def _weekday_short_ru(self, weekday_idx: int) -> str:
        weekdays = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"]
        return weekdays[weekday_idx]

    def _month_name_ru(self, month_num: int) -> str:
        month_names = {
            1: "января",
            2: "февраля",
            3: "марта",
            4: "апреля",
            5: "мая",
            6: "июня",
            7: "июля",
            8: "августа",
            9: "сентября",
            10: "октября",
            11: "ноября",
            12: "декабря",
        }
        return month_names[month_num]

    def _pair_number(self, start_time: str) -> str:
        pairs = {
            "06:50": "0",
            "08:30": "1",
            "10:15": "2",
            "12:00": "3",
            "14:15": "4",
            "16:00": "5",
            "17:40": "6",
            "19:15": "7",
            "20:50": "8",
        }
        return pairs.get(start_time, "•")



# ==============================
# UI
# ==============================
def main_menu_kb(is_authorized: bool):
    builder = InlineKeyboardBuilder()
    builder.button(text="📅 Сегодня", callback_data="menu:today")
    builder.button(text="🗓 Выбрать неделю", callback_data="menu:week:choose")
    builder.button(text="⏰ Напоминания", callback_data="menu:reminders")
    auth_text = "🔐 Профиль и сессия" if is_authorized else "🔐 Авторизоваться"
    builder.button(text=auth_text, callback_data="menu:auth")
    builder.adjust(1, 1, 1, 1)
    return builder.as_markup()


def week_nav_kb(current_offset: int):
    builder = InlineKeyboardBuilder()
    builder.button(text="⬅️ Пред.", callback_data=f"week:{current_offset - 1}")
    builder.button(text="Текущая", callback_data="week:0")
    builder.button(text="След. ➡️", callback_data=f"week:{current_offset + 1}")
    builder.button(text="📲 В календарь (iPhone)", callback_data=f"calendar:week:{current_offset}")
    builder.button(text="🗓 Выбрать неделю", callback_data="menu:week:choose")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(3, 1, 1, 1)
    return builder.as_markup()


def week_select_kb():
    builder = InlineKeyboardBuilder()
    builder.button(text="⬅️ Прошлая", callback_data="menu:week:-1")
    builder.button(text="📍 Текущая", callback_data="menu:week:0")
    builder.button(text="➡️ Следующая", callback_data="menu:week:1")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(3, 1)
    return builder.as_markup()


def day_select_kb(week_offset: int):
    builder = InlineKeyboardBuilder()
    builder.button(text="Пн", callback_data=f"day:pick:{week_offset}:0")
    builder.button(text="Вт", callback_data=f"day:pick:{week_offset}:1")
    builder.button(text="Ср", callback_data=f"day:pick:{week_offset}:2")
    builder.button(text="Чт", callback_data=f"day:pick:{week_offset}:3")
    builder.button(text="Пт", callback_data=f"day:pick:{week_offset}:4")
    builder.button(text="Сб", callback_data=f"day:pick:{week_offset}:5")
    builder.button(text="Вс", callback_data=f"day:pick:{week_offset}:6")
    builder.button(text="📚 Вся неделя", callback_data=f"day:week:{week_offset}")
    builder.button(text="⬅️ Пред. неделя", callback_data=f"menu:week:{week_offset - 1}")
    builder.button(text="След. неделя ➡️", callback_data=f"menu:week:{week_offset + 1}")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(4, 3, 1, 2, 1)
    return builder.as_markup()


def day_nav_kb(day_offset: int):
    builder = InlineKeyboardBuilder()
    builder.button(text="⬅️ Пред.", callback_data=f"today:offset:{day_offset - 1}")
    builder.button(text="📅 Сегодня", callback_data="today:offset:0")
    builder.button(text="След. ➡️", callback_data=f"today:offset:{day_offset + 1}")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(3, 1)
    return builder.as_markup()


def reminders_kb(enabled: bool, days: set[int]):
    builder = InlineKeyboardBuilder()
    toggle_text = "✅ Выключить напоминания" if enabled else "🔔 Включить напоминания"
    builder.button(text=toggle_text, callback_data="reminders:toggle")
    weekday_short = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
    for idx, day_name in enumerate(weekday_short):
        mark = "✅" if idx in days else "▫️"
        builder.button(text=f"{mark} {day_name}", callback_data=f"reminders:day:{idx}")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(1, 4, 3, 1)
    return builder.as_markup()


def auth_profile_kb():
    builder = InlineKeyboardBuilder()
    builder.button(text="🔁 Сменить аккаунт УрФУ", callback_data="auth:change")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(1, 1)
    return builder.as_markup()


def reply_schedule_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="📅 Расписание")]],
        resize_keyboard=True,
        input_field_placeholder="Быстрый доступ",
    )


# ==============================
# HELPERS
# ==============================

MONTHS_RU = {
    'января': 1,
    'февраля': 2,
    'марта': 3,
    'апреля': 4,
    'мая': 5,
    'июня': 6,
    'июля': 7,
    'августа': 8,
    'сентября': 9,
    'октября': 10,
    'ноября': 11,
    'декабря': 12,
}

WEEKDAY_NAMES_RU = {
    0: "Понедельник",
    1: "Вторник",
    2: "Среда",
    3: "Четверг",
    4: "Пятница",
    5: "Суббота",
    6: "Воскресенье",
}

def parse_russian_date(date_str: str) -> datetime:
    # '30 марта 2026 г.' -> datetime(2026, 3, 30)
    parts = date_str.replace(' г.', '').split()
    day = int(parts[0])
    month = MONTHS_RU[parts[1].lower()]
    year = int(parts[2])
    return datetime(year, month, day)


def lesson_type_emoji(lesson_type: str) -> str:
    normalized = (lesson_type or "").strip().lower()
    if "лек" in normalized:
        return "📖"
    if "лаб" in normalized:
        return "🧪"
    if "прак" in normalized or "сем" in normalized:
        return "🛠️"
    if "аттест" in normalized:
        return "📝"
    if "консульт" in normalized:
        return "💬"
    return "📘"


def is_online_place(place: str) -> bool:
    normalized = (place or "").strip().lower()
    if not normalized:
        return False
    online_markers = (
        "http://",
        "https://",
        "online",
        "teams.microsoft.com",
        "zoom.us",
        "meet.google.com",
        "inf-online",
    )
    return any(marker in normalized for marker in online_markers)

def format_lessons(title, lessons) -> str:
    if not lessons or (not lessons.get("offline") and not lessons.get("online")):
        return f"<b>{title}</b>\n\nПар нет 🎉"

    lines = [f"<b>{title}</b>", ""]
    all_lessons = [*lessons.get("offline", []), *lessons.get("online", [])]
    all_lessons.sort(
        key=lambda x: (
            parse_russian_date(x["date"]),
            x.get("time", ""),
        )
    )

    current_day = None

    for lesson in all_lessons:
        if lesson["date"] != current_day:
            current_day = lesson["date"]
            lines.append(f"📅 <b>{lesson['date_week'].upper()} · {lesson['date']}</b>")
            lines.append("────────────────")

        is_online = lesson.get("mode") == "online" or is_online_place(lesson.get("place", ""))
        place_icon = "💻" if is_online else "🏫"
        num = lesson.get("number_lesson", "•")
        pair_line = f"🔢 Пара: {num}" if str(num).isdigit() else None

        lines.append(
            f"<b>{num}. {lesson['name']}</b>\n"
            f"{pair_line + chr(10) if pair_line else ''}"
            f"🕒 <code>{lesson['time']}</code>\n"
            f"👨‍🏫 {lesson['teacher']}\n"
            f"{place_icon} {lesson['place']}\n"
            f"{lesson_type_emoji(lesson['type'])} {lesson['type']}"
        )
        lines.append("")

    return "\n".join(lines).strip()


async def safe_edit_message(callback: CallbackQuery, text: str, reply_markup=None) -> None:
    try:
        await callback.message.edit_text(text, reply_markup=reply_markup)
    except TelegramBadRequest as e:
        if "message is not modified" in str(e):
            logger.info("Message is not modified for callback user_id=%s", callback.from_user.id)
            return
        raise


async def acknowledge_callback(callback: CallbackQuery, text: str = "Загружаю...") -> None:
    try:
        await callback.answer(text)
    except TelegramBadRequest:
        logger.warning("Callback answer failed (maybe too old), user_id=%s", callback.from_user.id)


async def get_schedule_for_today(telegram_id: int) -> str:
    return await get_schedule_for_day(telegram_id, day_offset=0)


async def get_schedule_for_week(telegram_id: int, week_offset: int) -> str:
    try:
        lessons = await get_schedule_payload_for_week(telegram_id, week_offset)
    except Exception as e:
        logger.exception("Failed to get week schedule")
        return f"Не удалось получить расписание недели: <code>{e}</code>"

    monday, sunday = week_range_by_offset(week_offset)
    return format_lessons(
        f"Расписание недели {monday.strftime('%d.%m')} - {sunday.strftime('%d.%m')}",
        lessons,
    )


async def get_schedule_for_weekday(telegram_id: int, week_offset: int, weekday_idx: int) -> str:
    lessons = await get_schedule_payload_for_week(telegram_id, week_offset)
    filtered = {"online": [], "offline": []}

    for lesson in [*lessons.get("offline", []), *lessons.get("online", [])]:
        if parse_russian_date(lesson["date"]).weekday() == weekday_idx:
            bucket = "online" if lesson.get("mode") == "online" else "offline"
            filtered[bucket].append(lesson)

    monday, _ = week_range_by_offset(week_offset)
    day_date = monday + timedelta(days=weekday_idx)
    day_title = WEEKDAY_NAMES_RU.get(weekday_idx, "День")
    title = f"{day_title} ({day_date.strftime('%d.%m.%Y')})"
    return format_lessons(title, filtered)


async def get_schedule_for_day(telegram_id: int, day_offset: int) -> str:
    target_date = datetime.now(TIMEZONE).date() + timedelta(days=day_offset)
    current_monday = datetime.now(TIMEZONE).date() - timedelta(days=datetime.now(TIMEZONE).date().weekday())
    target_monday = target_date - timedelta(days=target_date.weekday())
    week_offset = (target_monday - current_monday).days // 7

    try:
        lessons = await get_schedule_payload_for_week(telegram_id, week_offset)
    except Exception as e:
        logger.exception("Failed to get day schedule")
        return f"Не удалось получить расписание дня: <code>{e}</code>"
    filtered = {"online": [], "offline": []}
    for lesson in [*lessons.get("offline", []), *lessons.get("online", [])]:
        if parse_russian_date(lesson["date"]).date() == target_date:
            bucket = "online" if lesson.get("mode") == "online" else "offline"
            filtered[bucket].append(lesson)

    day_name = WEEKDAY_NAMES_RU.get(target_date.weekday(), "День")
    return format_lessons(f"{day_name} ({target_date.strftime('%d.%m.%Y')})", filtered)


def filter_lessons_for_date(lessons: dict, target_date: datetime.date) -> dict:
    filtered = {"online": [], "offline": []}
    for lesson in [*lessons.get("offline", []), *lessons.get("online", [])]:
        if parse_russian_date(lesson["date"]).date() == target_date:
            bucket = "online" if lesson.get("mode") == "online" else "offline"
            filtered[bucket].append(lesson)
    return filtered


def lesson_start_datetime(lesson: dict) -> Optional[datetime]:
    try:
        target_date = parse_russian_date(lesson["date"]).date()
        start_time_str = lesson.get("time", "").split(" - ")[0].strip()
        hour, minute = map(int, start_time_str.split(":"))
        return datetime.combine(target_date, time(hour, minute), tzinfo=TIMEZONE)
    except Exception:
        return None


def lesson_datetime_range(lesson: dict) -> Optional[tuple[datetime, datetime]]:
    try:
        target_date = parse_russian_date(lesson["date"]).date()
        start_time_str, end_time_str = [part.strip() for part in lesson.get("time", "").split(" - ", 1)]
        start_hour, start_minute = map(int, start_time_str.split(":"))
        end_hour, end_minute = map(int, end_time_str.split(":"))
        start_dt = datetime.combine(target_date, time(start_hour, start_minute), tzinfo=TIMEZONE)
        end_dt = datetime.combine(target_date, time(end_hour, end_minute), tzinfo=TIMEZONE)
        return start_dt, end_dt
    except Exception:
        return None


def escape_ics_text(value: str) -> str:
    escaped = (value or "").replace("\\", "\\\\")
    escaped = escaped.replace("\n", "\\n").replace(",", "\\,").replace(";", "\\;")
    return escaped


def build_ics_calendar(telegram_id: int, lessons: dict, calendar_title: str) -> str:
    now_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//urfu-schedule-bot//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{escape_ics_text(calendar_title)}",
    ]

    all_lessons = [*lessons.get("offline", []), *lessons.get("online", [])]
    all_lessons.sort(key=lambda x: (parse_russian_date(x["date"]), x.get("time", "")))

    for lesson in all_lessons:
        date_range = lesson_datetime_range(lesson)
        if not date_range:
            continue
        start_dt, end_dt = date_range
        uid_source = (
            f"{telegram_id}|{lesson.get('date','')}|{lesson.get('time','')}|"
            f"{lesson.get('name','')}|{lesson.get('place','')}"
        )
        uid = f"{hashlib.sha1(uid_source.encode('utf-8')).hexdigest()}@urfu-schedule-bot"
        summary = escape_ics_text(lesson.get("name", "Пара"))
        description = escape_ics_text(
            f"Тип: {lesson.get('type', 'Не указано')}\n"
            f"Преподаватель: {lesson.get('teacher', 'Не указано')}\n"
            f"Пара: {lesson.get('number_lesson', '•')}"
        )
        location = escape_ics_text(lesson.get("place", "Не указано"))
        dtstart = start_dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dtend = end_dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        lines.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{now_utc}",
                f"DTSTART:{dtstart}",
                f"DTEND:{dtend}",
                f"SUMMARY:{summary}",
                f"DESCRIPTION:{description}",
                f"LOCATION:{location}",
                "END:VEVENT",
            ]
        )

    lines.append("END:VCALENDAR")
    return "\r\n".join(lines) + "\r\n"


def week_range_by_offset(week_offset: int) -> tuple[datetime.date, datetime.date]:
    now = datetime.now(TIMEZONE).date()
    monday = now - timedelta(days=now.weekday()) + timedelta(weeks=week_offset)
    sunday = monday + timedelta(days=6)
    return monday, sunday


async def get_schedule_payload_for_week(telegram_id: int, week_offset: int) -> dict:
    user = await get_user(telegram_id)
    if not user:
        raise ValueError("Сначала авторизуйся через кнопку «🔐 Авторизоваться».")

    has_login = bool((user.get("urfu_login") or "").strip())
    has_decryptable_password = bool(decrypt_password(user.get("urfu_password")))
    if not has_login or (not is_user_authorized(user) and not has_decryptable_password):
        raise ValueError("Сначала авторизуйся через кнопку «🔐 Авторизоваться».")

    return await fetch_schedule_payload_for_user(user, week_offset)


async def fetch_schedule_payload_for_user(user: dict, week_offset: int) -> dict:
    decrypted_password = decrypt_password(user.get("urfu_password"))
    async with UrfuScheduleClient() as client:
        lessons = await client.fetch_week_schedule(
            user["urfu_login"],
            decrypted_password,
            week_offset=week_offset,
            persisted_modeus_session=get_persisted_modeus_session(user),
        )
        if client.last_modeus_session:
            await save_modeus_session(
                user["telegram_id"],
                client.last_modeus_session["access_token"],
                client.last_modeus_session["person_id"],
                client.last_modeus_session["token_exp"],
            )
        return lessons


async def build_week_calendar_file(telegram_id: int, week_offset: int) -> tuple[str, BufferedInputFile, str]:
    lessons = await get_schedule_payload_for_week(telegram_id, week_offset)
    monday, sunday = week_range_by_offset(week_offset)
    title = f"УрФУ {monday.strftime('%d.%m')} - {sunday.strftime('%d.%m')}"
    ics_text = build_ics_calendar(telegram_id, lessons, calendar_title=title)
    filename = f"urfu_{monday.strftime('%Y%m%d')}_{sunday.strftime('%Y%m%d')}.ics"
    caption = (
        "📲 Файл календаря готов.\n"
        "На iPhone открой файл и нажми «Добавить все» в приложении Календарь."
    )
    return filename, BufferedInputFile(ics_text.encode("utf-8"), filename=filename), caption


def auth_status_text(user: Optional[dict]) -> str:
    if not user:
        return "🔐 <b>Статус:</b> не авторизован\n\nНажми кнопку «Авторизоваться», чтобы ввести логин и пароль."

    login = user.get("urfu_login")
    token_exp = user.get("modeus_token_exp")
    if not is_user_authorized(user):
        return (
            "🔐 <b>Статус:</b> частично настроено\n"
            f"👤 Логин: <code>{login or '—'}</code>\n"
            "Сессия Modeus не активна. Нажми «Авторизоваться», чтобы обновить вход."
        )

    try:
        exp_dt = datetime.fromtimestamp(int(token_exp), tz=timezone.utc).astimezone(TIMEZONE)
        exp_str = exp_dt.strftime("%d.%m.%Y %H:%M")
    except Exception:
        exp_str = "неизвестно"

    return (
        "🔐 <b>Статус:</b> авторизован ✅\n"
        f"👤 Логин: <code>{login}</code>\n"
        f"🆔 Person ID: <code>{user.get('modeus_person_id', '—')}</code>\n"
        f"⏳ Сессия до: <code>{exp_str}</code>\n"
        "🔒 Пароль хранится только в зашифрованном виде.\n"
        "Хранится: логин + шифрованный пароль + сессия Modeus."
    )


async def build_main_screen_text(telegram_id: int) -> tuple[str, bool]:
    user = await get_user(telegram_id)
    return WELCOME_TEXT, is_user_authorized(user)


# ==============================
# HANDLERS
# ==============================
@router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    _, authorized = await build_main_screen_text(message.from_user.id)
    await message.answer("Быстрый доступ включен 👇", reply_markup=reply_schedule_kb())
    await message.answer(WELCOME_TEXT, reply_markup=main_menu_kb(authorized))





@router.message(Command("login"))
async def cmd_login(message: Message, state: FSMContext) -> None:
    await message.answer(
        "🔐 Включаю режим авторизации.\n"
        "Мы бережно относимся к конфиденциальности:\n"
        "• пароль хранится только в зашифрованном виде,\n"
        "• сообщение с паролем удаляется после отправки."
    )
    await state.set_state(AuthStates.waiting_login)
    await message.answer("Введи логин от УрФУ:")


@router.message(AuthStates.waiting_login)
async def process_login(message: Message, state: FSMContext) -> None:
    login = message.text.strip()
    if not login:
        await message.answer("Логин пустой. Введи логин от УрФУ ещё раз:")
        return
    await state.update_data(urfu_login=login)
    await state.set_state(AuthStates.waiting_password)
    await message.answer(
        "Теперь введи пароль от УрФУ:\n"
        "🔒 Пароль будет зашифрован и сохранён для авто-обновления сессии.\n"
        "После отправки я удалю сообщение с паролем."
    )


@router.message(AuthStates.waiting_password)
async def process_password(message: Message, state: FSMContext) -> None:
    password = message.text.strip()
    try:
        await message.delete()
    except TelegramBadRequest:
        pass

    data = await state.get_data()
    login = data["urfu_login"]
    if not password:
        await message.answer("Пароль пустой. Введи пароль ещё раз:")
        return

    progress_message = await message.answer("🔄 Проверяю логин и пароль...")

    async def update_progress(text: str) -> None:
        try:
            await progress_message.edit_text(text)
        except TelegramBadRequest:
            await message.answer(text)

    async with UrfuScheduleClient() as client:
        ok = await client.login(login, password)

    if not ok:
        await update_progress("❌ Не удалось авторизоваться. Проверь логин/пароль.")
        await message.answer(
            "Не удалось авторизоваться. Проверь логин/пароль и попробуй снова через /login"
        )
        await state.clear()
        return

    await update_progress("🌐 Подключаю Modeus и создаю сессию...\nЭто может занять до 1-2 минут.")
    try:
        async with UrfuScheduleClient() as client:
            session_data = await client.bootstrap_modeus_session(login, password)
    except Exception as exc:
        logger.exception("Failed to bootstrap modeus session on login")
        error_text = str(exc).lower()
        if "неверный логин" in error_text or "пароль" in error_text:
            await update_progress("❌ Неверный логин или пароль.")
        else:
            await update_progress(
                "❌ Не удалось получить сессию Modeus. Проверь логин/пароль и попробуй снова."
            )
        await state.set_state(AuthStates.waiting_login)
        await message.answer("Введи логин от УрФУ ещё раз:")
        return

    await update_progress("✅ Сессия получена. Сохраняю логин и сессию...")
    await upsert_user_credentials(message.from_user.id, login, password)
    try:
        await save_modeus_session(
            message.from_user.id,
            session_data["access_token"],
            session_data["person_id"],
            session_data["token_exp"],
        )
        logger.info("Modeus session persisted for user_id=%s", message.from_user.id)
        await update_progress("✅ Сессия Modeus сохранена.")
    except Exception:
        logger.exception("Failed to persist modeus session on login")
        await update_progress("❌ Не удалось сохранить сессию. Попробуй авторизоваться ещё раз.")
        await state.set_state(AuthStates.waiting_login)
        await message.answer("Введи логин от УрФУ ещё раз:")
        return

    await state.clear()
    _, authorized = await build_main_screen_text(message.from_user.id)
    await message.answer("Готово! Данные сохранены.\nТеперь я смогу присылать расписание утром в 07:00.")
    await message.answer("Быстрый доступ включен 👇", reply_markup=reply_schedule_kb())
    await message.answer(WELCOME_TEXT, reply_markup=main_menu_kb(authorized))


@router.message(Command("today"))
async def cmd_today(message: Message) -> None:
    text = await get_schedule_for_day(message.from_user.id, day_offset=0)
    await message.answer(text, reply_markup=day_nav_kb(0))


@router.message(Command("week"))
async def cmd_week(message: Message) -> None:
    await message.answer("Выбери, какую неделю показать:", reply_markup=week_select_kb())


@router.message(F.text.in_(["📅 Расписание", "расписание", "Расписание"]))
async def reply_schedule_home(message: Message) -> None:
    _, authorized = await build_main_screen_text(message.from_user.id)
    await message.answer(WELCOME_TEXT, reply_markup=main_menu_kb(authorized))


@router.message(Command("calendar"))
async def cmd_calendar(message: Message) -> None:
    try:
        _, calendar_file, caption = await build_week_calendar_file(message.from_user.id, week_offset=0)
        await message.answer_document(document=calendar_file, caption=caption)
    except Exception as exc:
        await message.answer(f"Не удалось подготовить календарь: <code>{exc}</code>")


@router.callback_query(F.data == "menu:home")
async def cb_home(callback: CallbackQuery) -> None:
    await acknowledge_callback(callback, text="Открываю меню...")
    _, authorized = await build_main_screen_text(callback.from_user.id)
    await safe_edit_message(callback, WELCOME_TEXT, reply_markup=main_menu_kb(authorized))


@router.callback_query(F.data == "menu:today")
async def cb_menu_today(callback: CallbackQuery) -> None:
    logger.info("Callback menu:today from user_id=%s", callback.from_user.id)
    await acknowledge_callback(callback)
    text = await get_schedule_for_day(callback.from_user.id, day_offset=0)
    await safe_edit_message(callback, text, reply_markup=day_nav_kb(0))


@router.callback_query(F.data == "menu:reminders")
async def cb_menu_reminders(callback: CallbackQuery) -> None:
    await acknowledge_callback(callback, text="Открываю настройки...")
    user = await get_user(callback.from_user.id)
    if not is_user_authorized(user):
        await safe_edit_message(
            callback,
            "⏰ Настройки напоминаний доступны после авторизации.\n\nНажми «Авторизоваться».",
            reply_markup=main_menu_kb(False),
        )
        return

    enabled = bool(user and user.get("pair_reminders_enabled", 1))
    days = get_reminder_days(user)
    status = "включены ✅" if enabled else "выключены ⛔️"
    day_labels = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
    selected_days = ", ".join(day_labels[i] for i in sorted(days))
    text = (
        "⏰ <b>Напоминания о парах</b>\n\n"
        f"Сейчас: <b>{status}</b>\n"
        f"Дни: <b>{selected_days}</b>\n"
        "Напоминаю за <b>30 минут</b> и за <b>5 минут</b> до каждой пары."
    )
    await safe_edit_message(callback, text, reply_markup=reminders_kb(enabled, days))


@router.callback_query(F.data == "reminders:toggle")
async def cb_toggle_reminders(callback: CallbackQuery) -> None:
    await acknowledge_callback(callback)
    user = await get_user(callback.from_user.id)
    if not user:
        await safe_edit_message(
            callback,
            "Сначала авторизуйся через /login, чтобы включить напоминания.",
            reply_markup=main_menu_kb(False),
        )
        return

    new_enabled = not bool(user.get("pair_reminders_enabled", 1))
    await set_pair_reminders_enabled(callback.from_user.id, new_enabled)
    user["pair_reminders_enabled"] = 1 if new_enabled else 0
    days = get_reminder_days(user)
    status = "включены ✅" if new_enabled else "выключены ⛔️"
    day_labels = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
    selected_days = ", ".join(day_labels[i] for i in sorted(days))
    text = (
        "⏰ <b>Напоминания о парах</b>\n\n"
        f"Сейчас: <b>{status}</b>\n"
        f"Дни: <b>{selected_days}</b>\n"
        "Напоминаю за <b>30 минут</b> и за <b>5 минут</b> до каждой пары."
    )
    await safe_edit_message(callback, text, reply_markup=reminders_kb(new_enabled, days))


@router.callback_query(F.data.startswith("reminders:day:"))
async def cb_toggle_reminder_day(callback: CallbackQuery) -> None:
    await acknowledge_callback(callback)
    user = await get_user(callback.from_user.id)
    if not user:
        return
    try:
        day_idx = int(callback.data.split(":")[2])
    except (ValueError, IndexError):
        return
    if day_idx < 0 or day_idx > 6:
        return

    days = get_reminder_days(user)
    if day_idx in days:
        if len(days) == 1:
            await callback.answer("Хотя бы один день должен остаться включенным")
            return
        days.remove(day_idx)
    else:
        days.add(day_idx)

    await set_pair_reminder_days(callback.from_user.id, days)
    enabled = bool(user.get("pair_reminders_enabled", 1))
    day_labels = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
    selected_days = ", ".join(day_labels[i] for i in sorted(days))
    status = "включены ✅" if enabled else "выключены ⛔️"
    text = (
        "⏰ <b>Напоминания о парах</b>\n\n"
        f"Сейчас: <b>{status}</b>\n"
        f"Дни: <b>{selected_days}</b>\n"
        "Напоминаю за <b>30 минут</b> и за <b>5 минут</b> до каждой пары."
    )
    await safe_edit_message(callback, text, reply_markup=reminders_kb(enabled, days))


@router.callback_query(F.data == "menu:auth")
async def cb_menu_auth(callback: CallbackQuery, state: FSMContext) -> None:
    await acknowledge_callback(callback, text="Проверяю авторизацию...")
    user = await get_user(callback.from_user.id)
    if is_user_authorized(user):
        text = "🔐 <b>Профиль и сессия</b>\n\n" + auth_status_text(user)
        await safe_edit_message(callback, text, reply_markup=auth_profile_kb())
        return

    await state.set_state(AuthStates.waiting_login)
    await safe_edit_message(
        callback,
        "🔐 <b>Авторизация</b>\n\nВведи логин от УрФУ:",
        reply_markup=None,
    )


@router.callback_query(F.data == "auth:change")
async def cb_auth_change(callback: CallbackQuery, state: FSMContext) -> None:
    await acknowledge_callback(callback, text="Смена аккаунта...")
    await state.set_state(AuthStates.waiting_login)
    await safe_edit_message(
        callback,
        "🔁 <b>Смена аккаунта УрФУ</b>\n\nВведи новый логин:",
        reply_markup=None,
    )


@router.callback_query(F.data.startswith("today:offset:"))
async def cb_today_offset(callback: CallbackQuery) -> None:
    try:
        day_offset = int(callback.data.split(":")[2])
    except (ValueError, IndexError):
        return

    logger.info("Callback today:offset from user_id=%s day_offset=%s", callback.from_user.id, day_offset)
    await acknowledge_callback(callback)
    text = await get_schedule_for_day(callback.from_user.id, day_offset=day_offset)
    await safe_edit_message(callback, text, reply_markup=day_nav_kb(day_offset))


@router.callback_query(F.data == "menu:week:choose")
async def cb_menu_week_choose(callback: CallbackQuery) -> None:
    logger.info("Callback menu:week:choose from user_id=%s", callback.from_user.id)
    await acknowledge_callback(callback, text="Выбор недели...")
    await safe_edit_message(
        callback,
        "🗓 <b>Выбери неделю:</b>\n\nМожно посмотреть прошлую, текущую или следующую.",
        reply_markup=week_select_kb(),
    )


@router.callback_query(F.data.startswith("menu:week:"))
async def cb_menu_week(callback: CallbackQuery) -> None:
    try:
        week_offset = int(callback.data.split(":")[2])
    except (ValueError, IndexError):
        return
    logger.info("Callback menu:week from user_id=%s week_offset=%s", callback.from_user.id, week_offset)
    await acknowledge_callback(callback)
    monday, sunday = week_range_by_offset(week_offset)
    text = (
        "🗓 <b>Выбор дня</b>\n\n"
        f"Неделя: <b>{monday.strftime('%d.%m')} - {sunday.strftime('%d.%m')}</b>\n"
        "Выбери день недели ниже."
    )
    await safe_edit_message(callback, text, reply_markup=day_select_kb(week_offset))


@router.callback_query(F.data.startswith("day:pick:"))
async def cb_day_pick(callback: CallbackQuery) -> None:
    try:
        _, _, week_offset_raw, weekday_raw = callback.data.split(":")
        week_offset = int(week_offset_raw)
        weekday_idx = int(weekday_raw)
    except (ValueError, IndexError):
        return

    logger.info(
        "Callback day:pick from user_id=%s week_offset=%s weekday=%s",
        callback.from_user.id,
        week_offset,
        weekday_idx,
    )
    await acknowledge_callback(callback)
    text = await get_schedule_for_weekday(callback.from_user.id, week_offset=week_offset, weekday_idx=weekday_idx)
    await safe_edit_message(callback, text, reply_markup=day_select_kb(week_offset))


@router.callback_query(F.data.startswith("day:week:"))
async def cb_day_week(callback: CallbackQuery) -> None:
    try:
        week_offset = int(callback.data.split(":")[2])
    except (ValueError, IndexError):
        return

    logger.info("Callback day:week from user_id=%s week_offset=%s", callback.from_user.id, week_offset)
    await acknowledge_callback(callback)
    text = await get_schedule_for_week(callback.from_user.id, week_offset=week_offset)
    await safe_edit_message(callback, text, reply_markup=week_nav_kb(week_offset))


@router.callback_query(F.data.startswith("calendar:week:"))
async def cb_calendar_week(callback: CallbackQuery) -> None:
    try:
        week_offset = int(callback.data.split(":")[2])
    except (ValueError, IndexError):
        return
    await acknowledge_callback(callback, text="Готовлю файл календаря...")
    try:
        _, calendar_file, caption = await build_week_calendar_file(callback.from_user.id, week_offset=week_offset)
        await callback.message.answer_document(document=calendar_file, caption=caption)
    except Exception as exc:
        await callback.message.answer(f"Не удалось подготовить календарь: <code>{exc}</code>")



@router.callback_query(F.data == "auth")
async def cb_auth(callback: CallbackQuery, state: FSMContext) -> None:
    await cb_menu_auth(callback, state)


@router.callback_query(F.data.startswith("week:"))
async def cb_week(callback: CallbackQuery) -> None:
    week_offset = int(callback.data.split(":")[1])
    logger.info("Callback week:navigate from user_id=%s week_offset=%s", callback.from_user.id, week_offset)
    await acknowledge_callback(callback)
    text = await get_schedule_for_week(callback.from_user.id, week_offset=week_offset)
    await safe_edit_message(callback, text, reply_markup=week_nav_kb(week_offset))


@router.callback_query(F.data == "notif:on")
async def cb_notifications_on(callback: CallbackQuery) -> None:
    await set_notifications_enabled(callback.from_user.id, True)
    await callback.answer("Уведомления включены")
    await callback.message.answer("Утренние уведомления включены 🔔")


@router.callback_query(F.data == "notif:off")
async def cb_notifications_off(callback: CallbackQuery) -> None:
    await set_notifications_enabled(callback.from_user.id, False)
    await callback.answer("Уведомления выключены")
    await callback.message.answer("Утренние уведомления выключены 🔕")


# ==============================
# BACKGROUND DAILY SENDER
# ==============================
async def morning_scheduler(bot: Bot) -> None:
    while True:
        now = datetime.now(TIMEZONE)
        next_run = datetime.combine(now.date(), time(MORNING_HOUR, MORNING_MINUTE), tzinfo=TIMEZONE)
        if now >= next_run:
            next_run += timedelta(days=1)

        sleep_seconds = (next_run - now).total_seconds()
        logger.info("Scheduler sleeping for %.2f seconds until %s", sleep_seconds, next_run.isoformat())
        await asyncio.sleep(sleep_seconds)

        today_key = datetime.now(TIMEZONE).date().isoformat()
        users = await get_all_enabled_users()
        logger.info("Sending morning schedule to %d users", len(users))

        for user in users:
            telegram_id = user["telegram_id"]
            try:
                if await was_daily_notification_sent(telegram_id, today_key):
                    continue

                text = await get_schedule_for_today(telegram_id)
                await bot.send_message(
                    chat_id=telegram_id,
                    text=text,
                    disable_notification=True,
                )
                await mark_daily_notification_sent(telegram_id, today_key)
            except Exception:
                logger.exception("Failed to send morning schedule to user %s", telegram_id)

        await asyncio.sleep(2)


def format_pair_reminder_message(lesson: dict, minutes_left: int) -> str:
    mode = "💻 Онлайн" if lesson.get("mode") == "online" else "🏫 Оффлайн"
    return (
        f"⏰ <b>Напоминание: через {minutes_left} мин</b>\n\n"
        f"<b>{lesson.get('number_lesson', '•')}. {lesson['name']}</b>\n"
        f"📅 {lesson.get('date_week', '').upper()} · {lesson.get('date', 'Не указано')}\n"
        f"🕒 <code>{lesson['time']}</code>\n"
        f"👨‍🏫 {lesson['teacher']}\n"
        f"{mode}: {lesson['place']}\n"
        f"{lesson_type_emoji(lesson['type'])} {lesson['type']}"
    )


async def pair_reminder_scheduler(bot: Bot) -> None:
    reminder_offsets = (30, 5)
    tolerance_seconds = 55
    refresh_interval_seconds = 3600
    lessons_cache: dict[int, dict[str, Any]] = {}
    while True:
        now = datetime.now(TIMEZONE)
        users = await get_all_pair_reminder_users()
        for user in users:
            telegram_id = user["telegram_id"]
            try:
                if not is_user_authorized(user):
                    continue
                target_date = now.date()
                reminder_days = get_reminder_days(user)
                if target_date.weekday() not in reminder_days:
                    continue

                cache_entry = lessons_cache.get(telegram_id)
                needs_refresh = (
                    cache_entry is None
                    or cache_entry.get("date") != target_date.isoformat()
                    or (now.timestamp() - float(cache_entry.get("fetched_ts", 0))) >= refresh_interval_seconds
                )

                if needs_refresh:
                    current_monday = target_date - timedelta(days=target_date.weekday())
                    base_monday = datetime.now(TIMEZONE).date() - timedelta(days=datetime.now(TIMEZONE).date().weekday())
                    week_offset = (current_monday - base_monday).days // 7
                    lessons = await fetch_schedule_payload_for_user(user, week_offset)
                    today_lessons = filter_lessons_for_date(lessons, target_date)
                    lessons_cache[telegram_id] = {
                        "date": target_date.isoformat(),
                        "fetched_ts": now.timestamp(),
                        "today_lessons": today_lessons,
                    }
                    logger.info("Pair reminders data refreshed for user %s", telegram_id)
                else:
                    today_lessons = cache_entry["today_lessons"]

                for lesson in [*today_lessons["offline"], *today_lessons["online"]]:
                    start_dt = lesson_start_datetime(lesson)
                    if not start_dt:
                        continue
                    delta_sec = (start_dt - now).total_seconds()
                    if delta_sec < -tolerance_seconds:
                        continue

                    for minutes_left in reminder_offsets:
                        target_sec = minutes_left * 60
                        if abs(delta_sec - target_sec) <= tolerance_seconds:
                            reminder_key = (
                                f"{lesson['date']}|{lesson.get('time','')}|"
                                f"{lesson.get('name','')}|{minutes_left}"
                            )
                            if await was_pair_reminder_sent(telegram_id, reminder_key):
                                continue

                            await bot.send_message(
                                chat_id=telegram_id,
                                text=format_pair_reminder_message(lesson, minutes_left),
                            )
                            await mark_pair_reminder_sent(telegram_id, reminder_key)
                            logger.info(
                                "Pair reminder sent: user=%s lesson=%s in=%s min",
                                telegram_id,
                                lesson.get("name"),
                                minutes_left,
                            )
            except Exception:
                logger.exception("Failed pair reminder flow for user %s", telegram_id)

        sleep_seconds = 60 - datetime.now(TIMEZONE).second
        await asyncio.sleep(max(5, sleep_seconds))


# ==============================
# MAIN
# ==============================
async def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError("Set BOT_TOKEN in environment (.env)")
    if not (os.getenv("PASSWORD_ENCRYPTION_KEY") or "").strip():
        raise RuntimeError("Set PASSWORD_ENCRYPTION_KEY in environment (.env)")

    await init_db()

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)

    asyncio.create_task(morning_scheduler(bot))
    asyncio.create_task(pair_reminder_scheduler(bot))

    logger.info("Bot started")
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot stopped")
