import asyncio
import base64
import hashlib
import html
import json
import logging
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, time, timezone
from typing import Optional, List, Any
from urllib.parse import parse_qs, urlparse, urlencode
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

# ==============================
# CONFIG
# ==============================
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
DATABASE_PATH = os.getenv("DATABASE_PATH", "bot.db").strip() or "bot.db"
TIMEZONE = ZoneInfo("Asia/Yekaterinburg")
MORNING_HOUR = int(os.getenv("MORNING_HOUR", "7"))
MORNING_MINUTE = int(os.getenv("MORNING_MINUTE", "0"))
SCHEDULE_CACHE_TTL_SECONDS = int(os.getenv("SCHEDULE_CACHE_TTL_SECONDS", "900"))
BRS_CACHE_TTL_SECONDS = int(os.getenv("BRS_CACHE_TTL_SECONDS", "1800"))
STALE_CACHE_TTL_SECONDS = int(os.getenv("STALE_CACHE_TTL_SECONDS", "86400"))

ISTUDENT_BASE_URL = "https://istudent.urfu.ru"
ISTUDENT_LOGIN_URL = f"{ISTUDENT_BASE_URL}/student/login"
ISTUDENT_SCHEDULE_PAGE_URL = f"{ISTUDENT_BASE_URL}/s/schedule"
BASE_SCHEDULE_URL = "https://istudent.urfu.ru/s/schedule/schedule"
ISTUDENT_TOKEN_URL = "https://keys.urfu.ru/auth/realms/urfu-lk/protocol/openid-connect/token"
BRS_BASE_URL = "https://istudent.urfu.ru/s/http-urfu-ru-ru-students-study-brs"
URFU_PROXY_URL = (
    os.getenv("URFU_PROXY_URL")
    or os.getenv("HTTPS_PROXY")
    or os.getenv("HTTP_PROXY")
    or ""
).strip()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

router = Router()
_CACHE_LOCKS: dict[str, asyncio.Lock] = {}


WELCOME_TEXT = (
    "Привет! Я бот с расписанием УрФУ.\n\n"
    "Сначала авторизуйся один раз через кнопку 🔐, чтобы я мог получать твое расписание.\n\n"
    "Выбирай нужный раздел:\n"
    "• 📅 Сегодня\n"
    "• 🗓 Неделя\n"
    "• 📊 Баллы БРС\n"
    "• ⏰ Напоминания\n"
    "• 🔐 Профиль"
)


# ==============================
# DATABASE
# ==============================
CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    telegram_id INTEGER PRIMARY KEY,
    urfu_login TEXT NOT NULL,
    urfu_password TEXT NOT NULL,
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

CREATE_RESPONSE_CACHE_SQL = """
CREATE TABLE IF NOT EXISTS response_cache (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
"""


async def init_db() -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(CREATE_USERS_SQL)
        await db.execute(CREATE_SENT_LOG_SQL)
        await db.execute(CREATE_PAIR_REMINDER_LOG_SQL)
        await db.execute(CREATE_RESPONSE_CACHE_SQL)
        await ensure_users_columns(db)
        await db.commit()


async def ensure_users_columns(db: aiosqlite.Connection) -> None:
    cursor = await db.execute("PRAGMA table_info(users)")
    rows = await cursor.fetchall()
    existing = {row[1] for row in rows}
    required = {
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


def is_user_authorized(user: Optional[dict]) -> bool:
    if not user:
        return False
    if not user.get("urfu_login"):
        return False
    return bool(decrypt_password(user.get("urfu_password")))


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


def get_cache_lock(cache_key: str) -> asyncio.Lock:
    lock = _CACHE_LOCKS.get(cache_key)
    if lock is None:
        lock = asyncio.Lock()
        _CACHE_LOCKS[cache_key] = lock
    return lock


async def get_cached_response(cache_key: str, max_age_seconds: int) -> Optional[Any]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(CREATE_RESPONSE_CACHE_SQL)
        cursor = await db.execute(
            "SELECT payload, fetched_at FROM response_cache WHERE cache_key = ?",
            (cache_key,),
        )
        row = await cursor.fetchone()
    if not row:
        return None

    try:
        fetched_at = datetime.fromisoformat(row[1])
        age = (datetime.now(TIMEZONE) - fetched_at.astimezone(TIMEZONE)).total_seconds()
        if age > max_age_seconds:
            return None
        return json.loads(row[0])
    except Exception:
        logger.exception("Failed to read cached response for key=%s", cache_key)
        return None


async def set_cached_response(cache_key: str, payload: Any) -> None:
    try:
        payload_json = json.dumps(payload, ensure_ascii=False)
    except TypeError:
        logger.exception("Failed to serialize cached response for key=%s", cache_key)
        return

    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(CREATE_RESPONSE_CACHE_SQL)
        await db.execute(
            """
            INSERT INTO response_cache (cache_key, payload, fetched_at)
            VALUES (?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                payload = excluded.payload,
                fetched_at = excluded.fetched_at
            """,
            (cache_key, payload_json, datetime.now(TIMEZONE).isoformat()),
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


@dataclass
class BrsOption:
    value: str
    label: str
    selected: bool = False


@dataclass
class BrsDiscipline:
    discipline_id: str
    name: str
    score: str
    grade: str
    is_selected: bool
    is_actual: bool
    is_visible_by_default: bool
    survey_required: bool


@dataclass
class BrsReport:
    group_title: str
    program_title: str
    current_year: str
    current_year_label: str
    current_semester: str
    current_semester_label: str
    years: list[BrsOption]
    semesters: list[BrsOption]
    disciplines: list[BrsDiscipline]


@dataclass
class BrsDetailAttestation:
    title: str
    expression: str
    controls: list[str]


@dataclass
class BrsDetailSection:
    title: str
    expression: str
    attestations: list[BrsDetailAttestation]


@dataclass
class BrsDisciplineDetail:
    discipline_id: str
    name: str
    score: str
    site_grade: str
    teachers: list[str]
    sections: list[BrsDetailSection]


def brs_report_to_dict(report: BrsReport) -> dict[str, Any]:
    return asdict(report)


def brs_report_from_dict(data: dict[str, Any]) -> BrsReport:
    return BrsReport(
        group_title=data.get("group_title", ""),
        program_title=data.get("program_title", ""),
        current_year=data.get("current_year", ""),
        current_year_label=data.get("current_year_label", ""),
        current_semester=data.get("current_semester", ""),
        current_semester_label=data.get("current_semester_label", ""),
        years=[BrsOption(**item) for item in data.get("years", [])],
        semesters=[BrsOption(**item) for item in data.get("semesters", [])],
        disciplines=[BrsDiscipline(**item) for item in data.get("disciplines", [])],
    )


def brs_detail_to_dict(detail: BrsDisciplineDetail) -> dict[str, Any]:
    return asdict(detail)


def brs_detail_from_dict(data: dict[str, Any]) -> BrsDisciplineDetail:
    return BrsDisciplineDetail(
        discipline_id=data.get("discipline_id", ""),
        name=data.get("name", ""),
        score=data.get("score", ""),
        site_grade=data.get("site_grade", ""),
        teachers=list(data.get("teachers", [])),
        sections=[
            BrsDetailSection(
                title=section.get("title", ""),
                expression=section.get("expression", ""),
                attestations=[
                    BrsDetailAttestation(
                        title=attestation.get("title", ""),
                        expression=attestation.get("expression", ""),
                        controls=list(attestation.get("controls", [])),
                    )
                    for attestation in section.get("attestations", [])
                ],
            )
            for section in data.get("sections", [])
        ],
    )


def current_brs_period(today: Optional[datetime.date] = None) -> tuple[str, str]:
    current_date = today or datetime.now(TIMEZONE).date()
    if current_date.month >= 9:
        return str(current_date.year), "autumn"
    return str(current_date.year - 1), "spring"


def resolve_brs_period(year: Optional[str], semester: Optional[str]) -> tuple[str, str]:
    auto_year, auto_semester = current_brs_period()
    return year or auto_year, semester or auto_semester


def estimate_semester_number(group_title: str, academic_year: str, semester: str) -> Optional[int]:
    group_match = re.search(r"[-–](\d{2})", group_title or "")
    year_match = re.search(r"(\d{4})", academic_year or "")
    if not group_match or not year_match:
        return None

    enrollment_year = 2000 + int(group_match.group(1))
    academic_start_year = int(year_match.group(1))
    semester_number = (academic_start_year - enrollment_year) * 2
    semester_number += 1 if semester == "autumn" else 2
    return semester_number if semester_number > 0 else None


# ==============================
# URFU CLIENT
# ==============================
class UrfuScheduleClient:
    _istudent_token_cache: dict[str, dict[str, Any]] = {}

    def __init__(self) -> None:
        self.session: Optional[ClientSession] = None
        self.proxy_url: Optional[str] = URFU_PROXY_URL or None

    async def __aenter__(self):
        self.session = ClientSession(timeout=ClientTimeout(total=45), trust_env=True)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def login(self, login: str, password: str) -> bool:
        if self.session is None:
            raise RuntimeError("Session is not initialized")

        if not login or not password:
            return False
        try:
            await self._fetch_istudent_access_token(login, password, force_refresh=True)
            return True
        except Exception:
            logger.exception("iStudent auth check failed for user %s", login.strip().lower())
            return False

    async def fetch_week_schedule(
        self,
        login: str,
        password: Optional[str],
        week_offset: int = 0,
    ) -> dict:
        if self.session is None:
            raise RuntimeError("Session is not initialized")

        logger.info("Fetch week schedule requested: week_offset=%s", week_offset)
        logger.info("Trying iStudent schedule flow")
        return await self.fetch_istudent_week_schedule(login, password or "", week_offset)


    async def fetch_today_schedule(
        self,
        login: str,
        password: Optional[str],
    ) -> dict:
        all_week = await self.fetch_week_schedule(
            login,
            password,
            week_offset=0,
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

    async def fetch_istudent_week_schedule(
        self,
        login: str,
        password: str,
        week_offset: int,
    ) -> dict:
        if self.session is None:
            raise RuntimeError("Session is not initialized")
        if not login or not password:
            raise ValueError("Для расписания iStudent нужен сохраненный логин и пароль УрФУ.")

        token = await self._fetch_istudent_access_token(login, password)
        headers = self._istudent_headers(referer=ISTUDENT_SCHEDULE_PAGE_URL, ajax=True)
        cookies = {"keycloakAccessToken": token}

        login_resp = await self.session.get(
            self._build_istudent_login_url(ISTUDENT_SCHEDULE_PAGE_URL),
            headers=headers,
            cookies=cookies,
            allow_redirects=True,
            proxy=self.proxy_url,
        )
        await login_resp.text()
        if login_resp.status != 200:
            raise ValueError(f"iStudent авторизация вернула статус {login_resp.status}")

        monday, sunday = self._week_range(week_offset)
        combined = {"online": [], "offline": []}
        seen_lessons = set()
        for window_start in (monday, monday - timedelta(days=7)):
            start_time = int(datetime.combine(window_start, time(0, 0), tzinfo=TIMEZONE).timestamp())
            resp = await self.session.get(
                BASE_SCHEDULE_URL,
                params={"startTime": start_time},
                headers=headers,
                cookies=cookies,
                allow_redirects=True,
                proxy=self.proxy_url,
            )
            payload = await resp.text()
            if resp.status != 200:
                raise ValueError(f"iStudent расписание вернуло статус {resp.status}")
            if "/student/keycloak-login" in str(resp.url):
                raise ValueError("Не удалось создать сессию iStudent для расписания.")

            parsed = self._filter_schedule_by_period(
                self.parse_schedule_html(payload),
                monday,
                sunday,
            )
            for bucket in ("offline", "online"):
                for lesson in parsed.get(bucket, []):
                    key = (
                        lesson.get("date"),
                        lesson.get("time"),
                        lesson.get("number_lesson"),
                        lesson.get("name"),
                        lesson.get("place"),
                    )
                    if key in seen_lessons:
                        continue
                    seen_lessons.add(key)
                    combined[bucket].append(lesson)
            if combined["offline"] or combined["online"]:
                break
        return combined

    async def fetch_brs_report(
        self,
        login: str,
        password: Optional[str],
        year: Optional[str] = None,
        semester: Optional[str] = None,
    ) -> BrsReport:
        if self.session is None:
            raise RuntimeError("Session is not initialized")
        if not login or not password:
            raise ValueError("Для БРС нужен сохраненный логин и пароль УрФУ.")

        token = await self._fetch_istudent_access_token(login, password)
        headers = self._istudent_headers(referer=BRS_BASE_URL)
        cookies = {"keycloakAccessToken": token}

        login_resp = await self.session.get(
            self._build_istudent_login_url(BRS_BASE_URL),
            headers=headers,
            cookies=cookies,
            allow_redirects=True,
            proxy=self.proxy_url,
        )
        await login_resp.text()
        if login_resp.status != 200:
            raise ValueError(f"iStudent авторизация вернула статус {login_resp.status}")

        brs_url = self._build_brs_url(year=year, semester=semester)
        resp = await self.session.get(
            brs_url,
            headers=headers,
            cookies=cookies,
            allow_redirects=True,
            proxy=self.proxy_url,
        )
        payload = await resp.text()
        if resp.status != 200:
            raise ValueError(f"БРС вернул статус {resp.status}")
        if "/student/keycloak-login" in str(resp.url):
            raise ValueError("Не удалось создать сессию iStudent для БРС.")

        return self.parse_brs_html(payload)

    async def fetch_brs_discipline_detail(
        self,
        login: str,
        password: Optional[str],
        discipline: BrsDiscipline,
        year: Optional[str] = None,
        semester: Optional[str] = None,
    ) -> BrsDisciplineDetail:
        if self.session is None:
            raise RuntimeError("Session is not initialized")
        if not login or not password:
            raise ValueError("Для детализации БРС нужен сохраненный логин и пароль УрФУ.")
        if not discipline.discipline_id:
            raise ValueError("У дисциплины нет идентификатора для детализации.")

        token = await self._fetch_istudent_access_token(login, password)
        headers = self._istudent_headers(referer=BRS_BASE_URL, ajax=True)
        cookies = {"keycloakAccessToken": token}
        report_url = self._build_brs_url(year=year, semester=semester)

        login_resp = await self.session.get(
            self._build_istudent_login_url(report_url),
            headers=headers,
            cookies=cookies,
            allow_redirects=True,
            proxy=self.proxy_url,
        )
        await login_resp.text()
        if login_resp.status != 200:
            raise ValueError(f"iStudent авторизация вернула статус {login_resp.status}")

        report_resp = await self.session.get(
            report_url,
            headers=headers,
            cookies=cookies,
            allow_redirects=True,
            proxy=self.proxy_url,
        )
        await report_resp.text()
        if report_resp.status != 200:
            raise ValueError(f"БРС вернул статус {report_resp.status}")

        detail_resp = await self.session.get(
            f"{BRS_BASE_URL}/discipline",
            params={
                "disciplineId": discipline.discipline_id,
                "backlink": str(report_resp.url),
            },
            headers=headers,
            cookies=cookies,
            allow_redirects=True,
            proxy=self.proxy_url,
        )
        payload = await detail_resp.text()
        if detail_resp.status != 200:
            raise ValueError(f"Детализация БРС вернула статус {detail_resp.status}")
        if "/student/keycloak-login" in str(detail_resp.url):
            raise ValueError("Не удалось создать сессию iStudent для детализации БРС.")

        return self.parse_brs_discipline_detail_html(payload, discipline)

    async def _fetch_istudent_access_token(self, login: str, password: str, force_refresh: bool = False) -> str:
        if self.session is None:
            raise RuntimeError("Session is not initialized")

        cache_key = login.strip().lower()
        now_ts = int(datetime.now(timezone.utc).timestamp())
        cached = self._istudent_token_cache.get(cache_key)
        if (
            cached
            and not force_refresh
            and cached.get("password_hash") == hashlib.sha256(password.encode("utf-8")).hexdigest()
            and int(cached.get("exp") or 0) - 60 > now_ts
        ):
            return cached["token"]

        resp = await self.session.post(
            ISTUDENT_TOKEN_URL,
            data={
                "grant_type": "password",
                "client_id": "istudent",
                "username": login,
                "password": password,
                "scope": "openid",
            },
            headers={"Accept": "application/json"},
            proxy=self.proxy_url,
        )
        try:
            payload = await resp.json(content_type=None)
        except Exception as exc:
            raise ValueError(f"Keycloak iStudent вернул статус {resp.status}") from exc

        if resp.status != 200:
            error = (payload.get("error_description") or payload.get("error") or "").lower()
            if "invalid" in error or "парол" in error or "credential" in error:
                raise ValueError("Неверный логин или пароль УрФУ для iStudent.")
            raise ValueError(f"Keycloak iStudent вернул статус {resp.status}")

        token = payload.get("access_token")
        if not token:
            raise ValueError("Keycloak iStudent не вернул access_token")
        claims = self._decode_jwt_payload(token)
        exp = int(claims.get("exp") or (now_ts + 300))
        self._istudent_token_cache[cache_key] = {
            "token": token,
            "exp": exp,
            "password_hash": hashlib.sha256(password.encode("utf-8")).hexdigest(),
        }
        return token

    def _decode_jwt_payload(self, token: str) -> dict[str, Any]:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return {}
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8"))
        except Exception:
            return {}

    def _build_brs_url(self, year: Optional[str] = None, semester: Optional[str] = None) -> str:
        params = {}
        if year and year != "0":
            params["year"] = year
        if semester and semester != "0":
            params["semester"] = semester
        if not params:
            return BRS_BASE_URL
        return f"{BRS_BASE_URL}?{urlencode(params)}"

    def _build_istudent_login_url(self, backlink_url: str) -> str:
        backlink = backlink_url.replace("https://", "http://", 1)
        return f"{ISTUDENT_LOGIN_URL}?{urlencode({'backlink': backlink})}"

    def _istudent_headers(self, referer: str, ajax: bool = False) -> dict[str, str]:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9",
            "Referer": referer,
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
            ),
        }
        if ajax:
            headers["Accept"] = "text/html, */*; q=0.01"
            headers["X-Requested-With"] = "XMLHttpRequest"
        return headers

    def _week_range(self, week_offset: int = 0):
        now = datetime.now(TIMEZONE).date()
        monday = now - timedelta(days=now.weekday()) + timedelta(weeks=week_offset)
        sunday = monday + timedelta(days=6)
        return monday, sunday

    def _filter_schedule_by_period(self, schedule: dict, monday, sunday) -> dict:
        filtered = {"online": [], "offline": []}
        for bucket in ("offline", "online"):
            for lesson in schedule.get(bucket, []):
                try:
                    lesson_date = parse_russian_date(lesson["date"]).date()
                except Exception:
                    continue
                if monday <= lesson_date <= sunday:
                    filtered[bucket].append(lesson)
        return filtered

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
            date_el = block.find('div', class_='date')
            date_week_el = block.find('div', class_='day-on-week')
            if not date_el or not date_week_el:
                continue
            date = date_el.text.strip().replace('\u202f', ' ')
            date_week = date_week_el.text.strip().replace('\u202f', ' ')
            if not re.search(r"\d{1,2}\s+\S+\s+\d{4}", date):
                continue
            if date in seen_dates:
                continue
            seen_dates.add(date)

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

                    elif self._looks_like_schedule_place(info):
                        place_lesson = info

                    elif self._looks_like_schedule_type(info):
                        type_lesson = self._normalize_istudent_lesson_type(info)

                    elif type_lesson == "Не указано":
                        type_lesson = info

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

                        elif self._looks_like_schedule_place(info):
                            place_lesson = info

                        elif self._looks_like_schedule_type(info):
                            type_lesson = self._normalize_istudent_lesson_type(info)

                        elif type_lesson == "Не указано":
                            type_lesson = info
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

    def _looks_like_schedule_place(self, value: str) -> bool:
        normalized = (value or "").strip().lower()
        if not normalized:
            return False
        place_markers = (
            "http://",
            "https://",
            "teams.microsoft.com",
            "zoom.us",
            "meet.google.com",
            "мира",
            "тургенева",
            "куйбышева",
            "софьи ковалевской",
            "комсомольская",
            "малышева",
            "ленина",
            "ауд",
            "место проведения",
            "гибридный формат",
        )
        if any(marker in normalized for marker in place_markers):
            return True
        return bool(re.search(r"\b[рх]\s*\d", normalized))

    def _looks_like_schedule_type(self, value: str) -> bool:
        normalized = (value or "").strip().lower()
        if not normalized:
            return False
        type_markers = (
            "лекц",
            "практ",
            "лаборатор",
            "семинар",
            "зачет",
            "зачёт",
            "экзамен",
            "консультац",
            "аттеста",
            "курсов",
        )
        return any(marker in normalized for marker in type_markers)

    def _normalize_istudent_lesson_type(self, value: str) -> str:
        normalized = (value or "").strip().lower()
        if "лекц" in normalized:
            return "Лекция"
        if "лаборатор" in normalized:
            return "Лаба"
        if "практ" in normalized or "семинар" in normalized:
            return "Практика"
        if "консультац" in normalized:
            return "Консультация"
        if "аттеста" in normalized:
            return "Аттестация"
        if "экзамен" in normalized:
            return "Экзамен"
        if "зач" in normalized:
            return "Зачет"
        return self._normalize_text(value)

    def parse_brs_html(self, payload: str) -> BrsReport:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(payload, "html.parser")
        if not soup.select(".discipline") and not soup.select("#year-select"):
            raise ValueError("Не удалось найти данные БРС на странице iStudent")

        years = self._parse_brs_options(soup, "#year-select", "year")
        semesters = self._parse_brs_options(soup, "#semester-select", "semester")
        current_year = next((item for item in years if item.selected), None)
        current_semester = next((item for item in semesters if item.selected), None)
        group_option = soup.select_one("#group-select option[selected]") or soup.select_one("#group-select option")
        program = soup.select_one(".education-service-info")

        disciplines: list[BrsDiscipline] = []
        for discipline in soup.select(".discipline"):
            classes = set(discipline.get("class", []))
            parent_classes = set((discipline.parent or {}).get("class", []))
            header = discipline.select_one(".discipline-header")
            if not header:
                continue

            name_cell = header.select_one(".td-0")
            if not name_cell:
                continue
            mobile_mark = name_cell.select_one(".mobile-discipline-mark")
            if mobile_mark:
                mobile_mark.extract()

            name = self._normalize_text(name_cell.get_text(" ", strip=True))
            score_cell = header.select_one(".td-1")
            grade_cell = header.select_one(".td-2")
            score = self._normalize_text(score_cell.get_text(" ", strip=True) if score_cell else "")
            grade = self._normalize_text(grade_cell.get_text(" ", strip=True) if grade_cell else "")
            if not name:
                continue

            disciplines.append(
                BrsDiscipline(
                    discipline_id=str(discipline.get("data-id") or "").strip(),
                    name=name,
                    score=score or "—",
                    grade=grade or "—",
                    is_selected="not-selected" not in classes,
                    is_actual="not-actual" not in classes,
                    is_visible_by_default="hidden" not in parent_classes,
                    survey_required=bool(discipline.select_one(".survey-flag")),
                )
            )

        return BrsReport(
            group_title=self._normalize_text(group_option.get_text(" ", strip=True)) if group_option else "",
            program_title=self._normalize_text(program.get_text(" ", strip=True)) if program else "",
            current_year=current_year.value if current_year else "",
            current_year_label=current_year.label if current_year else "",
            current_semester=current_semester.value if current_semester else "",
            current_semester_label=current_semester.label if current_semester else "",
            years=years,
            semesters=semesters,
            disciplines=disciplines,
        )

    def _parse_brs_options(self, soup, selector: str, query_key: str) -> list[BrsOption]:
        options: list[BrsOption] = []
        for option in soup.select(f"{selector} option"):
            raw_url = option.get("value") or ""
            parsed = urlparse(raw_url)
            query = parse_qs(parsed.query)
            value = (query.get(query_key) or [""])[0]
            label = self._normalize_text(option.get_text(" ", strip=True))
            if label:
                options.append(
                    BrsOption(
                        value=value,
                        label=label,
                        selected=option.has_attr("selected"),
                    )
                )
        return options

    def parse_brs_discipline_detail_html(
        self,
        payload: str,
        discipline: BrsDiscipline,
    ) -> BrsDisciplineDetail:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(payload, "html.parser")
        if not soup.select(".discipline-detail") and not soup.select(".discipline-mark"):
            raise ValueError("Не удалось найти детализацию дисциплины БРС")

        teachers: list[str] = []
        sections: list[BrsDetailSection] = []
        score = discipline.score
        site_grade = discipline.grade

        mark = soup.select_one(".discipline-mark")
        if mark:
            mark_texts = [
                self._normalize_text(item.get_text(" ", strip=True))
                for item in mark.select("p")
            ]
            for item in mark_texts:
                lower = item.lower()
                if lower.startswith("оценка:"):
                    site_grade = self._normalize_text(item.split(":", 1)[1])
                elif lower.startswith("балл:"):
                    score = self._normalize_text(item.split(":", 1)[1])

        for detail in soup.select(".discipline-detail"):
            header = detail.select_one(".discipline-detail-header")
            title, expression = self._parse_brs_detail_header(header)
            if not title:
                continue

            if title.lower().startswith("преподаватели"):
                teachers = [
                    self._normalize_text(item.get_text(" ", strip=True))
                    for item in detail.select(".list .detail-inline-block")
                    if self._normalize_text(item.get_text(" ", strip=True))
                ]
                continue

            attestations: list[BrsDetailAttestation] = []
            for attestation in detail.select(".discipline-attestation"):
                att_title, att_expression = self._parse_brs_detail_header(
                    attestation.select_one(".discipline-attestation-header")
                )
                controls = [
                    self._normalize_text(item.get_text(" ", strip=True))
                    for item in attestation.select(".discipline-controls p")
                    if self._normalize_text(item.get_text(" ", strip=True))
                ]
                if att_title or att_expression or controls:
                    attestations.append(
                        BrsDetailAttestation(
                            title=att_title,
                            expression=att_expression,
                            controls=controls,
                        )
                    )

            sections.append(
                BrsDetailSection(
                    title=title,
                    expression=expression,
                    attestations=attestations,
                )
            )

        return BrsDisciplineDetail(
            discipline_id=discipline.discipline_id,
            name=discipline.name,
            score=score or discipline.score,
            site_grade=site_grade or discipline.grade,
            teachers=teachers,
            sections=sections,
        )

    def _parse_brs_detail_header(self, header) -> tuple[str, str]:
        if not header:
            return "", ""
        from bs4 import BeautifulSoup

        expression_el = header.select_one(".score-expression-desktop") or header.select_one(".score-expression-mobile")
        expression = self._normalize_text(expression_el.get_text(" ", strip=True)) if expression_el else ""

        title_el = header.find("span", recursive=False)
        if not title_el:
            raw = self._normalize_text(header.get_text(" ", strip=True))
            return raw, expression

        title_soup = BeautifulSoup(str(title_el), "html.parser")
        for item in title_soup.select(".mobile-factor"):
            item.decompose()
        title = self._normalize_text(title_soup.get_text(" ", strip=True)).rstrip(":")
        return title, expression

    def _normalize_text(self, value: str) -> str:
        return " ".join((value or "").replace("\xa0", " ").split())

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
    builder.button(text="🗓 Неделя", callback_data="menu:week:choose")
    builder.button(text="📊 Баллы БРС", callback_data="menu:brs")
    builder.button(text="⏰ Напоминания", callback_data="menu:reminders")
    auth_text = "🔐 Профиль" if is_authorized else "🔐 Авторизоваться"
    builder.button(text=auth_text, callback_data="menu:auth")
    builder.adjust(1, 1, 1, 1, 1)
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
    target_date = datetime.now(TIMEZONE).date() + timedelta(days=day_offset)
    current_monday = datetime.now(TIMEZONE).date() - timedelta(days=datetime.now(TIMEZONE).date().weekday())
    target_monday = target_date - timedelta(days=target_date.weekday())
    week_offset = (target_monday - current_monday).days // 7
    builder.button(text="⬅️ Пред.", callback_data=f"today:offset:{day_offset - 1}")
    builder.button(text="📅 Сегодня", callback_data="today:offset:0")
    builder.button(text="След. ➡️", callback_data=f"today:offset:{day_offset + 1}")
    builder.button(text="🗓 Дни недели", callback_data=f"menu:week:{week_offset}")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(3, 1, 1)
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


def brs_report_kb(report: BrsReport, include_hidden: bool):
    builder = InlineKeyboardBuilder()
    year = brs_callback_value(report.current_year)
    semester = brs_callback_value(report.current_semester)
    mode = "actual"

    builder.button(
        text=f"📅 Год: {report.current_year_label or 'выбрать'}",
        callback_data=f"brs:years:{year}:{semester}:{mode}",
    )
    builder.button(
        text=f"🌓 Семестр: {report.current_semester_label or 'выбрать'}",
        callback_data=f"brs:semesters:{year}:{semester}:{mode}",
    )
    builder.button(text="📚 Предметы подробно", callback_data=f"brs:list:{year}:{semester}:{mode}")
    builder.button(text="🔄 Обновить из УрФУ", callback_data=f"brs:refresh:{year}:{semester}:{mode}")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(1, 1, 1, 1, 1)
    return builder.as_markup()


def brs_year_select_kb(report: BrsReport, include_hidden: bool):
    builder = InlineKeyboardBuilder()
    semester = brs_callback_value(report.current_semester)
    mode = "actual"
    for option in report.years:
        mark = "✅ " if option.selected else ""
        builder.button(
            text=f"{mark}{option.label}",
            callback_data=f"brs:show:{brs_callback_value(option.value)}:{semester}:{mode}",
        )
    builder.button(
        text="⬅️ Назад",
        callback_data=f"brs:show:{brs_callback_value(report.current_year)}:{semester}:{mode}",
    )
    builder.adjust(1)
    return builder.as_markup()


def brs_semester_select_kb_values(year: Optional[str], semester: Optional[str]):
    builder = InlineKeyboardBuilder()
    year_value = brs_callback_value(year)
    current_semester = brs_callback_value(semester)
    for value, label in (("autumn", "Осенний"), ("spring", "Весенний")):
        mark = "✅ " if value == current_semester else ""
        builder.button(
            text=f"{mark}{label}",
            callback_data=f"brs:show:{year_value}:{value}:actual",
        )
    builder.button(
        text="⬅️ Назад",
        callback_data=f"brs:show:{year_value}:{current_semester}:actual",
    )
    builder.adjust(1)
    return builder.as_markup()


def active_brs_disciplines(report: BrsReport) -> list[BrsDiscipline]:
    return [
        item for item in report.disciplines
        if item.is_visible_by_default and item.is_actual and item.is_selected
    ]


def brs_subject_select_kb(report: BrsReport):
    builder = InlineKeyboardBuilder()
    year = brs_callback_value(report.current_year)
    semester = brs_callback_value(report.current_semester)
    for idx, discipline in enumerate(active_brs_disciplines(report), start=1):
        score = discipline.score or "—"
        builder.button(
            text=f"{idx}. {shorten_text(discipline.name, 42)} · {score}",
            callback_data=f"brsd:show:{year}:{semester}:{discipline.discipline_id}",
        )
    builder.button(text="⬅️ К БРС", callback_data=f"brs:show:{year}:{semester}:actual")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(1)
    return builder.as_markup()


def brs_detail_kb(year: Optional[str], semester: Optional[str]):
    builder = InlineKeyboardBuilder()
    year_value = brs_callback_value(year)
    semester_value = brs_callback_value(semester)
    builder.button(text="📚 Все предметы", callback_data=f"brs:list:{year_value}:{semester_value}:actual")
    builder.button(text="⬅️ К БРС", callback_data=f"brs:show:{year_value}:{semester_value}:actual")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(1, 1, 1)
    return builder.as_markup()


def auth_profile_kb():
    builder = InlineKeyboardBuilder()
    builder.button(text="🔁 Сменить аккаунт УрФУ", callback_data="auth:change")
    builder.button(text="🏠 Меню", callback_data="menu:home")
    builder.adjust(1, 1)
    return builder.as_markup()


def reply_schedule_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="📅 Расписание"), KeyboardButton(text="📊 БРС")]],
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


def brs_callback_value(value: Optional[str]) -> str:
    return (value or "0").strip() or "0"


def brs_semester_label(value: Optional[str]) -> str:
    labels = {
        "autumn": "Осенний",
        "spring": "Весенний",
    }
    return labels.get((value or "").strip(), "семестр")


def brs_year_label(value: Optional[str]) -> str:
    try:
        year = int((value or "").strip())
        return f"{year}/{year + 1}"
    except ValueError:
        return "учебный год"


def brs_loading_text(year: Optional[str] = None, semester: Optional[str] = None, force_refresh: bool = False) -> str:
    if not year or not semester:
        year, semester = current_brs_period()
    action = "Обновляю данные из УрФУ" if force_refresh else "Загружаю БРС"
    source = "Если недавно открывал, покажу из кэша." if not force_refresh else "Это может занять несколько секунд."
    return (
        f"📊 <b>{action}...</b>\n\n"
        f"🗓 {html.escape(brs_year_label(year))} · {html.escape(brs_semester_label(semester))}\n"
        f"⏳ {source}"
    )


def schedule_loading_text(title: str, detail: str) -> str:
    return (
        f"🗓 <b>{html.escape(title)}...</b>\n\n"
        f"{html.escape(detail)}\n"
        "⏳ Загружаю расписание. Если оно уже открывалось, покажу из кэша."
    )


def brs_decode_callback_value(value: str) -> Optional[str]:
    value = (value or "").strip()
    return None if not value or value == "0" else value


def brs_mode_value(include_hidden: bool) -> str:
    return "all" if include_hidden else "actual"


def brs_mode_is_all(value: str) -> bool:
    return value == "all"


def shorten_text(value: str, limit: int = 96) -> str:
    value = " ".join((value or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def parse_brs_score(score: str) -> Optional[float]:
    try:
        normalized = (score or "").replace(",", ".").strip()
        return float(normalized)
    except ValueError:
        return None


def brs_score_grade(score: str) -> tuple[str, str]:
    value = parse_brs_score(score)
    if value is None:
        return "Нет данных", "📌"
    if value < 40:
        return "Неудовлетворительно", "🔴"
    if value < 60:
        return "Удовлетворительно", "🟡"
    if value < 80:
        return "Хорошо", "🟢"
    return "Отлично", "🏆"


def brs_score_bar(score: str) -> str:
    value = parse_brs_score(score)
    if value is None:
        return "▫️" * 10
    filled = max(0, min(10, round(value / 10)))
    return "🟩" * filled + "⬜" * (10 - filled)


def brs_is_pending_result(score: str, grade: str) -> bool:
    value = parse_brs_score(score)
    normalized_grade = (grade or "").strip().lower()
    return (
        value == 0
        and (
            "отсутств" in normalized_grade
            or "незач" in normalized_grade
            or "неуд" in normalized_grade
        )
    )


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


def format_brs_report(report: BrsReport, include_hidden: bool = False) -> str:
    visible_disciplines = active_brs_disciplines(report)
    semester_number = estimate_semester_number(
        report.group_title,
        report.current_year_label,
        report.current_semester,
    )
    semester_title = (
        f"{semester_number} семестр"
        if semester_number
        else report.current_semester_label or "семестр"
    )

    lines = [
        f"📊 <b>БРС · {html.escape(semester_title)}</b>",
        "",
        f"🎓 <b>{html.escape(report.group_title or '—')}</b>",
        f"🗓 {html.escape(report.current_year_label or '—')} · {html.escape(report.current_semester_label or '—')}",
    ]
    if report.program_title:
        lines.append(f"📚 {html.escape(report.program_title)}")
    lines.append("✅ Только актуальные дисциплины")
    lines.append("📐 Оценка рассчитана по баллам")
    lines.append("")

    if not visible_disciplines:
        lines.append("По текущему семестру баллы пока не найдены.")
        return "\n".join(lines).strip()

    for idx, discipline in enumerate(visible_disciplines, start=1):
        name = html.escape(shorten_text(discipline.name, limit=110))
        score = html.escape(discipline.score or "—")
        grade, grade_icon = brs_score_grade(discipline.score)
        grade = html.escape(grade)
        is_pending = brs_is_pending_result(discipline.score, discipline.grade)
        survey_line = "\n🧾 Нужно заполнить анкету" if discipline.survey_required else ""
        pending_label = " · в процессе" if is_pending else ""
        lines.append(
            f"{idx}. <b>{name}</b>\n"
            f"<b>{score}</b>/100 · {grade_icon} <b>{grade}</b>{pending_label}\n"
            f"{brs_score_bar(discipline.score)}"
            f"{survey_line}"
        )
        lines.append("")

    text = "\n".join(lines).strip()
    if len(text) <= 3900:
        return text

    trimmed = lines[:6]
    for line in lines[6:]:
        candidate = "\n".join([*trimmed, line, "\nСписок сокращен: сообщение Telegram слишком длинное."])
        if len(candidate) > 3900:
            break
        trimmed.append(line)
    trimmed.append("\nСписок сокращен: сообщение Telegram слишком длинное.")
    return "\n".join(trimmed).strip()


def format_brs_subject_list(report: BrsReport) -> str:
    disciplines = active_brs_disciplines(report)
    semester_number = estimate_semester_number(
        report.group_title,
        report.current_year_label,
        report.current_semester,
    )
    semester_title = f"{semester_number} семестр" if semester_number else report.current_semester_label or "семестр"
    return (
        f"📚 <b>Предметы БРС · {html.escape(semester_title)}</b>\n\n"
        f"🗓 {html.escape(report.current_year_label or '—')} · {html.escape(report.current_semester_label or '—')}\n"
        f"Выбери предмет, чтобы посмотреть детализацию баллов.\n\n"
        f"Доступно предметов: <b>{len(disciplines)}</b>"
    )


def format_brs_detail(detail: BrsDisciplineDetail, report: BrsReport) -> str:
    grade, grade_icon = brs_score_grade(detail.score)
    lines = [
        f"📘 <b>{html.escape(shorten_text(detail.name, 120))}</b>",
        f"🗓 {html.escape(report.current_year_label or '—')} · {html.escape(report.current_semester_label or '—')}",
        "",
        f"<b>{html.escape(detail.score or '—')}</b>/100 · {grade_icon} <b>{html.escape(grade)}</b>",
        brs_score_bar(detail.score),
    ]

    if detail.teachers:
        lines.extend(["", "👨‍🏫 <b>Преподаватели</b>"])
        lines.extend(f"• {html.escape(teacher)}" for teacher in detail.teachers)

    if detail.sections:
        lines.append("")

    for section in detail.sections:
        lines.append(f"<b>{html.escape(section.title)}</b>")
        if section.expression:
            lines.append(f"Итог блока: {html.escape(section.expression)}")
        for attestation in section.attestations:
            attestation_line = f"• {html.escape(attestation.title)}"
            if attestation.expression:
                attestation_line += f": {html.escape(attestation.expression)}"
            lines.append(attestation_line)
            for control in attestation.controls:
                lines.append(f"  - {html.escape(control)}")
        lines.append("")

    text = "\n".join(lines).strip()
    if len(text) <= 3900:
        return text

    trimmed = lines[:8]
    for line in lines[8:]:
        candidate = "\n".join([*trimmed, line, "\nДетализация сокращена: сообщение Telegram слишком длинное."])
        if len(candidate) > 3900:
            break
        trimmed.append(line)
    trimmed.append("\nДетализация сокращена: сообщение Telegram слишком длинное.")
    return "\n".join(trimmed).strip()


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


async def get_brs_report_payload(
    telegram_id: int,
    year: Optional[str] = None,
    semester: Optional[str] = None,
    force_refresh: bool = False,
) -> BrsReport:
    user = await get_user(telegram_id)
    if not user:
        raise ValueError("Сначала авторизуйся через кнопку «🔐 Авторизоваться».")

    year, semester = resolve_brs_period(year, semester)
    cache_key = f"brs:v2:{telegram_id}:{year}:{semester}"
    if not force_refresh:
        cached = await get_cached_response(cache_key, BRS_CACHE_TTL_SECONDS)
        if cached:
            logger.info("BRS cache hit for user=%s year=%s semester=%s", telegram_id, year, semester)
            return brs_report_from_dict(cached)

    login = (user.get("urfu_login") or "").strip()
    decrypted_password = decrypt_password(user.get("urfu_password"))
    if not login or not decrypted_password:
        raise ValueError("Для БРС нужен сохраненный пароль. Заново авторизуйся через «🔐 Авторизоваться».")

    async with get_cache_lock(cache_key):
        if not force_refresh:
            cached = await get_cached_response(cache_key, BRS_CACHE_TTL_SECONDS)
            if cached:
                logger.info("BRS cache hit after lock for user=%s year=%s semester=%s", telegram_id, year, semester)
                return brs_report_from_dict(cached)

        try:
            async with UrfuScheduleClient() as client:
                report = await client.fetch_brs_report(
                    login,
                    decrypted_password,
                    year=year,
                    semester=semester,
                )
            await set_cached_response(cache_key, brs_report_to_dict(report))
            return report
        except Exception:
            stale = await get_cached_response(cache_key, STALE_CACHE_TTL_SECONDS)
            if stale:
                logger.exception("BRS fetch failed, returning stale cache for user=%s", telegram_id)
                return brs_report_from_dict(stale)
            raise


async def build_brs_response(
    telegram_id: int,
    year: Optional[str] = None,
    semester: Optional[str] = None,
    include_hidden: bool = False,
    force_refresh: bool = False,
) -> tuple[str, Any, BrsReport]:
    report = await get_brs_report_payload(
        telegram_id,
        year=year,
        semester=semester,
        force_refresh=force_refresh,
    )
    return format_brs_report(report, include_hidden=include_hidden), brs_report_kb(report, include_hidden), report


async def get_brs_discipline_detail_payload(
    telegram_id: int,
    discipline_id: str,
    year: Optional[str] = None,
    semester: Optional[str] = None,
    force_refresh: bool = False,
) -> tuple[BrsDisciplineDetail, BrsReport]:
    year, semester = resolve_brs_period(year, semester)
    report = await get_brs_report_payload(telegram_id, year=year, semester=semester)
    discipline = next(
        (
            item for item in active_brs_disciplines(report)
            if item.discipline_id == discipline_id
        ),
        None,
    )
    if discipline is None:
        raise ValueError("Предмет не найден в актуальных дисциплинах БРС.")

    cache_key = f"brs_detail:v1:{telegram_id}:{year}:{semester}:{discipline_id}"
    if not force_refresh:
        cached = await get_cached_response(cache_key, BRS_CACHE_TTL_SECONDS)
        if cached:
            logger.info("BRS detail cache hit for user=%s discipline=%s", telegram_id, discipline_id)
            return brs_detail_from_dict(cached), report

    user = await get_user(telegram_id)
    if not user:
        raise ValueError("Сначала авторизуйся через кнопку «🔐 Авторизоваться».")

    login = (user.get("urfu_login") or "").strip()
    decrypted_password = decrypt_password(user.get("urfu_password"))
    if not login or not decrypted_password:
        raise ValueError("Для детализации БРС нужен сохраненный пароль. Заново авторизуйся через «🔐 Авторизоваться».")

    async with get_cache_lock(cache_key):
        if not force_refresh:
            cached = await get_cached_response(cache_key, BRS_CACHE_TTL_SECONDS)
            if cached:
                logger.info("BRS detail cache hit after lock for user=%s discipline=%s", telegram_id, discipline_id)
                return brs_detail_from_dict(cached), report

        try:
            async with UrfuScheduleClient() as client:
                detail = await client.fetch_brs_discipline_detail(
                    login,
                    decrypted_password,
                    discipline,
                    year=year,
                    semester=semester,
                )
            await set_cached_response(cache_key, brs_detail_to_dict(detail))
            return detail, report
        except Exception:
            stale = await get_cached_response(cache_key, STALE_CACHE_TTL_SECONDS)
            if stale:
                logger.exception(
                    "BRS detail fetch failed, returning stale cache for user=%s discipline=%s",
                    telegram_id,
                    discipline_id,
                )
                return brs_detail_from_dict(stale), report
            raise


async def fetch_schedule_payload_for_user(user: dict, week_offset: int, force_refresh: bool = False) -> dict:
    telegram_id = user["telegram_id"]
    cache_key = f"schedule:v2:{telegram_id}:{week_offset}"
    if not force_refresh:
        cached = await get_cached_response(cache_key, SCHEDULE_CACHE_TTL_SECONDS)
        if cached:
            logger.info("Schedule cache hit for user=%s week_offset=%s", telegram_id, week_offset)
            return cached

    decrypted_password = decrypt_password(user.get("urfu_password"))
    async with get_cache_lock(cache_key):
        if not force_refresh:
            cached = await get_cached_response(cache_key, SCHEDULE_CACHE_TTL_SECONDS)
            if cached:
                logger.info("Schedule cache hit after lock for user=%s week_offset=%s", telegram_id, week_offset)
                return cached

        try:
            async with UrfuScheduleClient() as client:
                lessons = await client.fetch_week_schedule(
                    user["urfu_login"],
                    decrypted_password,
                    week_offset=week_offset,
                )
            await set_cached_response(cache_key, lessons)
            return lessons
        except Exception:
            stale = await get_cached_response(cache_key, STALE_CACHE_TTL_SECONDS)
            if stale:
                logger.exception("Schedule fetch failed, returning stale cache for user=%s week_offset=%s", telegram_id, week_offset)
                return stale
            raise


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
    has_password = bool(decrypt_password(user.get("urfu_password")))
    if has_password:
        return (
            "🔐 <b>Статус:</b> авторизован ✅\n"
            f"👤 Логин: <code>{login or '—'}</code>\n"
            "Источник расписания: <b>iStudent УрФУ</b>\n"
            "БРС: <b>iStudent УрФУ</b>\n"
            "🔒 Пароль хранится только в зашифрованном виде."
        )

    if not is_user_authorized(user):
        return (
            "🔐 <b>Статус:</b> частично настроено\n"
            f"👤 Логин: <code>{login or '—'}</code>\n"
            "Пароль не сохранен. Нажми «Авторизоваться», чтобы включить iStudent."
        )

    return (
        "🔐 <b>Статус:</b> частично настроено\n"
        f"👤 Логин: <code>{login or '—'}</code>\n"
        "Заново авторизуйся через «🔐 Авторизоваться», чтобы включить iStudent."
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
        "🔒 Пароль будет зашифрован и сохранён для получения расписания и БРС.\n"
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

    await update_progress("✅ Вход iStudent подтвержден. Сохраняю данные...")
    await upsert_user_credentials(message.from_user.id, login, password)
    await update_progress("✅ Данные сохранены. Расписание и БРС будут работать через iStudent.")

    await state.clear()
    _, authorized = await build_main_screen_text(message.from_user.id)
    await message.answer("Готово. Теперь я смогу отправлять расписание утром.")
    await message.answer("Быстрый доступ включен 👇", reply_markup=reply_schedule_kb())
    await message.answer(WELCOME_TEXT, reply_markup=main_menu_kb(authorized))


@router.message(Command("today"))
async def cmd_today(message: Message) -> None:
    progress = await message.answer(schedule_loading_text("Открываю день", "Сегодня"))
    text = await get_schedule_for_day(message.from_user.id, day_offset=0)
    await progress.edit_text(text, reply_markup=day_nav_kb(0))


@router.message(Command("week"))
async def cmd_week(message: Message) -> None:
    await message.answer("Выбери, какую неделю показать:", reply_markup=week_select_kb())


@router.message(Command("brs"))
async def cmd_brs(message: Message) -> None:
    progress = await message.answer(brs_loading_text())
    try:
        text, keyboard, _ = await build_brs_response(message.from_user.id)
        await progress.edit_text(text, reply_markup=keyboard)
    except Exception as exc:
        logger.exception("Failed to get BRS")
        await progress.edit_text(f"Не удалось получить БРС: <code>{exc}</code>")


@router.message(F.text.in_(["📅 Расписание", "расписание", "Расписание"]))
async def reply_schedule_home(message: Message) -> None:
    _, authorized = await build_main_screen_text(message.from_user.id)
    await message.answer(WELCOME_TEXT, reply_markup=main_menu_kb(authorized))


@router.message(F.text.in_(["📊 БРС", "брс", "БРС"]))
async def reply_brs(message: Message) -> None:
    await cmd_brs(message)


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
    await safe_edit_message(callback, schedule_loading_text("Открываю день", "Сегодня"), reply_markup=None)
    text = await get_schedule_for_day(callback.from_user.id, day_offset=0)
    await safe_edit_message(callback, text, reply_markup=day_nav_kb(0))


@router.callback_query(F.data == "menu:brs")
async def cb_menu_brs(callback: CallbackQuery) -> None:
    logger.info("Callback menu:brs from user_id=%s", callback.from_user.id)
    await acknowledge_callback(callback, text="Загружаю БРС...")
    try:
        await safe_edit_message(callback, brs_loading_text(), reply_markup=None)
        text, keyboard, _ = await build_brs_response(callback.from_user.id)
        await safe_edit_message(callback, text, reply_markup=keyboard)
    except Exception as exc:
        logger.exception("Failed to get BRS")
        await safe_edit_message(
            callback,
            f"Не удалось получить БРС: <code>{exc}</code>",
            reply_markup=main_menu_kb(False),
        )


@router.callback_query(F.data.startswith("brs:"))
async def cb_brs(callback: CallbackQuery) -> None:
    await acknowledge_callback(callback, text="Обновляю БРС...")
    parts = (callback.data or "").split(":")
    if len(parts) < 5:
        return

    action = parts[1]
    year = brs_decode_callback_value(parts[2])
    semester = brs_decode_callback_value(parts[3])
    include_hidden = brs_mode_is_all(parts[4])
    force_refresh = action == "refresh"

    try:
        if action == "semesters":
            if not year:
                year, semester = resolve_brs_period(year, semester)
            await safe_edit_message(
                callback,
                "🌓 <b>Выбери семестр БРС</b>",
                reply_markup=brs_semester_select_kb_values(year, semester),
            )
            return

        if action == "list":
            await safe_edit_message(
                callback,
                "📚 <b>Открываю предметы...</b>\n\n⏳ Готовлю список актуальных дисциплин.",
                reply_markup=None,
            )
            report = await get_brs_report_payload(
                callback.from_user.id,
                year=year,
                semester=semester,
            )
            await safe_edit_message(
                callback,
                format_brs_subject_list(report),
                reply_markup=brs_subject_select_kb(report),
            )
            return

        loading_title = "Открываю выбор" if action in {"years", "semesters"} else None
        if loading_title:
            await safe_edit_message(
                callback,
                f"📊 <b>{loading_title}...</b>\n\n⏳ Загружаю доступные периоды БРС.",
                reply_markup=None,
            )
        else:
            await safe_edit_message(
                callback,
                brs_loading_text(year=year, semester=semester, force_refresh=force_refresh),
                reply_markup=None,
            )
        report = await get_brs_report_payload(
            callback.from_user.id,
            year=year,
            semester=semester,
            force_refresh=force_refresh,
        )
        if action == "years":
            await safe_edit_message(
                callback,
                "📅 <b>Выбери учебный год БРС</b>",
                reply_markup=brs_year_select_kb(report, include_hidden),
            )
            return

        text = format_brs_report(report, include_hidden=include_hidden)
        await safe_edit_message(callback, text, reply_markup=brs_report_kb(report, include_hidden))
    except Exception as exc:
        logger.exception("Failed to handle BRS callback")
        await safe_edit_message(
            callback,
            f"Не удалось получить БРС: <code>{exc}</code>",
            reply_markup=main_menu_kb(False),
        )


@router.callback_query(F.data.startswith("brsd:"))
async def cb_brs_detail(callback: CallbackQuery) -> None:
    await acknowledge_callback(callback, text="Открываю предмет...")
    parts = (callback.data or "").split(":")
    if len(parts) < 5:
        return

    action = parts[1]
    year = brs_decode_callback_value(parts[2])
    semester = brs_decode_callback_value(parts[3])
    discipline_id = parts[4]
    force_refresh = action == "refresh"

    try:
        await safe_edit_message(
            callback,
            "📘 <b>Открываю предмет...</b>\n\n⏳ Загружаю детализацию баллов.",
            reply_markup=None,
        )
        detail, report = await get_brs_discipline_detail_payload(
            callback.from_user.id,
            discipline_id,
            year=year,
            semester=semester,
            force_refresh=force_refresh,
        )
        await safe_edit_message(
            callback,
            format_brs_detail(detail, report),
            reply_markup=brs_detail_kb(report.current_year, report.current_semester),
        )
    except Exception as exc:
        logger.exception("Failed to handle BRS discipline detail callback")
        year, semester = resolve_brs_period(year, semester)
        await safe_edit_message(
            callback,
            f"Не удалось открыть детализацию предмета: <code>{exc}</code>",
            reply_markup=brs_detail_kb(year, semester),
        )


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
        text = "🔐 <b>Профиль iStudent</b>\n\n" + auth_status_text(user)
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
    target_date = datetime.now(TIMEZONE).date() + timedelta(days=day_offset)
    day_name = WEEKDAY_NAMES_RU.get(target_date.weekday(), "День")
    await safe_edit_message(
        callback,
        schedule_loading_text("Открываю день", f"{day_name}, {target_date.strftime('%d.%m.%Y')}"),
        reply_markup=None,
    )
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
    monday, _ = week_range_by_offset(week_offset)
    target_date = monday + timedelta(days=weekday_idx)
    day_name = WEEKDAY_NAMES_RU.get(weekday_idx, "День")
    await safe_edit_message(
        callback,
        schedule_loading_text("Открываю день", f"{day_name}, {target_date.strftime('%d.%m.%Y')}"),
        reply_markup=None,
    )
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
    monday, sunday = week_range_by_offset(week_offset)
    await safe_edit_message(
        callback,
        schedule_loading_text("Открываю неделю", f"{monday.strftime('%d.%m')} - {sunday.strftime('%d.%m')}"),
        reply_markup=None,
    )
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
    monday, sunday = week_range_by_offset(week_offset)
    await safe_edit_message(
        callback,
        schedule_loading_text("Открываю неделю", f"{monday.strftime('%d.%m')} - {sunday.strftime('%d.%m')}"),
        reply_markup=None,
    )
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
