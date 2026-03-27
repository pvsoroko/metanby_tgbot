import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Union
import csv
import asyncpg
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.redis import RedisStorage
from aiogram.utils.keyboard import InlineKeyboardBuilder, ReplyKeyboardBuilder
from aiogram.types import Message, CallbackQuery, ReplyKeyboardRemove, BufferedInputFile, InlineKeyboardButton, InlineKeyboardMarkup
from pydantic import BaseModel, EmailStr, ValidationError, field_validator
from dotenv import load_dotenv
import redis
import asyncio
import shutil
from cryptography.fernet import Fernet
import re
from aiogram.exceptions import TelegramBadRequest
import aiohttp
import gzip
import traceback
import json
import html

# Создаём необходимые директории
os.makedirs("logs", exist_ok=True)
os.makedirs("temp", exist_ok=True)
os.makedirs("backups", exist_ok=True)
os.makedirs("temp/delayed_photos", exist_ok=True)

# ==================== НАСТРОЙКА ЛОГИРОВАНИЯ ====================

class SecurityFilter(logging.Filter):
    """Маскирует личные данные в логах"""
    def __init__(self, mask_phone=True, mask_email=True, mask_passport=True, mask_iban=True):
        super().__init__()
        self.mask_phone = mask_phone
        self.mask_email = mask_email
        self.mask_passport = mask_passport
        self.mask_iban = mask_iban
    
    def filter(self, record):
        if isinstance(record.msg, str):
            original = record.msg
            
            # Маскируем телефоны (+375XXXXXXXXX -> +375*****)
            if self.mask_phone:
                record.msg = re.sub(r'(\+375)(\d{2})(\d{3})(\d{4})', r'\1**\3****', record.msg)
            
            # Маскируем email (user@domain.com -> ***@domain.com)
            if self.mask_email:
                record.msg = re.sub(r'([\w\.-]+)(@[\w\.-]+\.\w{2,})', r'***\2', record.msg)
            
            # Маскируем номера паспортов (MP1234567 -> MP*****)
            if self.mask_passport:
                record.msg = re.sub(r'([A-Z]{2})(\d{7})', r'\1*****', record.msg)
                record.msg = re.sub(r'(\d{7}[A-Z]{2})', r'*****\1', record.msg)
            
            # Маскируем IBAN счета
            if self.mask_iban:
                record.msg = re.sub(r'(IBAN BY)(\w{4})(\w+)(\w{4})', r'\1\2****\4', record.msg)
            
            # Логируем факт маскировки
            if original != record.msg:
                logger = logging.getLogger('security')
                logger.debug(f"Замаскированы личные данные в сообщении")
        
        return True

class ColoredFormatter(logging.Formatter):
    """Добавляет цвета в консоль для разных уровней логирования"""
    COLORS = {
        'DEBUG': '\x1b[36m',      # Cyan
        'INFO': '\x1b[32m',        # Green
        'WARNING': '\x1b[33m',     # Yellow
        'ERROR': '\x1b[31m',       # Red
        'CRITICAL': '\x1b[35m',    # Magenta
        'RESET': '\x1b[0m'
    }
    
    def format(self, record):
        # Добавляем цвет для уровня
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        
        # Добавляем цвет для имени логгера
        record.name = f"\x1b[33m{record.name}\x1b[0m"
        
        # Форматируем время
        record.asctime = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        
        return super().format(record)

def setup_logging():
    """Настройка системы логирования"""
    
    # Корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Очищаем существующие обработчики
    root_logger.handlers.clear()
    
    # Формат для файлов (без цветов, но с деталями)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # === 1. Основной лог (bot.log) - все события с маскировкой ===
    bot_handler = RotatingFileHandler(
        "logs/bot.log",
        maxBytes=50*1024*1024,  # 50 MB
        backupCount=20,
        encoding='utf-8'
    )
    bot_handler.setLevel(logging.INFO)
    bot_handler.setFormatter(file_formatter)
    bot_handler.addFilter(SecurityFilter(
        mask_phone=True,
        mask_email=True,
        mask_passport=True,
        mask_iban=True
    ))
    root_logger.addHandler(bot_handler)
    
    # === 2. Лог ошибок (errors.log) - только ошибки ===
    error_handler = RotatingFileHandler(
        "logs/errors.log",
        maxBytes=20*1024*1024,  # 20 MB
        backupCount=10,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    error_handler.addFilter(SecurityFilter(
        mask_phone=True,
        mask_email=True,
        mask_passport=True,
        mask_iban=True
    ))
    root_logger.addHandler(error_handler)
    
    # === 3. Отладочный лог (debug.log) - максимально подробно, без маскировки ===
    debug_handler = RotatingFileHandler(
        "logs/debug.log",
        maxBytes=50*1024*1024,  # 50 MB
        backupCount=5,
        encoding='utf-8'
    )
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s\n"
        "  Thread: %(threadName)s, Process: %(processName)s\n"
        "  Path: %(pathname)s",
        datefmt="%Y-%m-%d %H:%M:%S.%f"
    ))
    # Для debug.log не применяем маскировку
    root_logger.addHandler(debug_handler)
    
    # === 4. Консольный вывод (цветной) ===
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_formatter = ColoredFormatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # === 5. Отдельный лог для входящих запросов ===
    requests_logger = logging.getLogger('requests')
    requests_handler = RotatingFileHandler(
        "logs/requests.log",
        maxBytes=20*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    requests_handler.setLevel(logging.DEBUG)
    requests_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    requests_logger.addHandler(requests_handler)
    requests_logger.propagate = False
    
    # === 6. Лог для базы данных ===
    db_logger = logging.getLogger('db')
    db_handler = RotatingFileHandler(
        "logs/database.log",
        maxBytes=20*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    db_handler.setLevel(logging.DEBUG)
    db_handler.setFormatter(file_formatter)
    db_logger.addHandler(db_handler)
    db_logger.propagate = False
    
    # === 7. Лог безопасности ===
    security_logger = logging.getLogger('security')
    security_handler = RotatingFileHandler(
        "logs/security.log",
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    security_handler.setLevel(logging.INFO)
    security_handler.setFormatter(file_formatter)
    security_logger.addHandler(security_handler)
    security_logger.propagate = False
    
    # Настройка уровней для сторонних библиотек
    logging.getLogger('aiogram').setLevel(logging.INFO)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('redis').setLevel(logging.WARNING)
    logging.getLogger('asyncpg').setLevel(logging.WARNING)
    
    return root_logger

# Инициализация логирования
logger = setup_logging()
logger.info("="*80)
logger.info("🚀 БОТ ЗАПУЩЕН")
logger.info("="*80)

# Специализированные логгеры
requests_logger = logging.getLogger('requests')
db_logger = logging.getLogger('db')
security_logger = logging.getLogger('security')

# ==================== ЗАГРУЗКА КОНФИГУРАЦИИ ====================

load_dotenv()

class Config:
    def __init__(self):
        self.BOT_TOKEN = os.getenv("BOT_TOKEN")
        
        # Поддержка списка администраторов через ADMIN_IDS или ADMIN_ID
        admin_ids_str = os.getenv("ADMIN_IDS", "")
        if admin_ids_str:
            self.ADMIN_IDS = [int(id.strip()) for id in admin_ids_str.split(",") if id.strip()]
        else:
            admin_id = os.getenv("ADMIN_ID")
            if admin_id:
                self.ADMIN_IDS = [int(admin_id)]
            else:
                raise ValueError("ADMIN_ID or ADMIN_IDS is required")
        
        self.MODERATOR_IDS = [int(id) for id in os.getenv("MODERATOR_IDS", "").split(",") if id]
        self.AGNKS_IDS = [int(id) for id in os.getenv("AGNKS_IDS", "").split(",") if id]
        self.SITE_NEWS_URL = os.getenv("SITE_NEWS_URL")
        self.SITE_SECRET_TOKEN = os.getenv("SITE_SECRET_TOKEN")
        self.POSTGRES_DSN = os.getenv("POSTGRES_DSN")
        self.REDIS_HOST = os.getenv("REDIS_HOST")
        self.REDIS_PORT = int(os.getenv("REDIS_PORT"))
        self.REDIS_DB = int(os.getenv("REDIS_DB"))
        self.ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
        self.ENVIRONMENT = os.getenv("ENVIRONMENT")
        
        # Новая настройка: ID Telegram-группы для публикации новостей
        self.TELEGRAM_GROUP_ID = os.getenv("TELEGRAM_GROUP_ID")
        if self.TELEGRAM_GROUP_ID:
            try:
                self.TELEGRAM_GROUP_ID = int(self.TELEGRAM_GROUP_ID)
            except ValueError:
                logger.warning("TELEGRAM_GROUP_ID должен быть числом, будет проигнорирован")
                self.TELEGRAM_GROUP_ID = None
        
        if not self.BOT_TOKEN:
            raise ValueError("BOT_TOKEN is required")
        if not self.ADMIN_IDS:
            raise ValueError("ADMIN_IDS is required")
        
        logger.info(f"📝 Конфигурация загружена. Admin IDs: {self.ADMIN_IDS}")

config = Config()

# ==================== ИНИЦИАЛИЗАЦИЯ БОТА ====================

bot = Bot(token=config.BOT_TOKEN)
storage = RedisStorage.from_url(f"redis://{config.REDIS_HOST}:{config.REDIS_PORT}/{config.REDIS_DB}")
dp = Dispatcher(storage=storage)

# Redis клиент
redis_client = redis.Redis(
    host=config.REDIS_HOST,
    port=config.REDIS_PORT,
    db=config.REDIS_DB,
    decode_responses=True
)
logger.info(f"📦 Redis подключен: {config.REDIS_HOST}:{config.REDIS_PORT}")

# ==================== ШИФРОВАНИЕ ====================

cipher_suite = Fernet(config.ENCRYPTION_KEY.encode())

def encrypt_data(data: str) -> str:
    try:
        encrypted = cipher_suite.encrypt(data.encode()).decode()
        security_logger.info(f"Данные зашифрованы (первые 5 символов: {data[:5]}...)")
        return encrypted
    except Exception as e:
        logger.error(f"Ошибка шифрования: {e}", exc_info=True)
        raise

def decrypt_data(encrypted_data: str) -> str:
    try:
        decrypted = cipher_suite.decrypt(encrypted_data.encode()).decode()
        security_logger.info(f"Данные расшифрованы (первые 5 символов: {decrypted[:5]}...)")
        return decrypted
    except Exception as e:
        logger.error(f"Ошибка расшифровки: {e}", exc_info=True)
        raise

# ==================== КОНСТАНТЫ ====================

EMOJI_NEW = "🆕"
EMOJI_DONE = "✅"
EMOJI_WARNING = "⚠️"
EMOJI_ERROR = "❌"
EMOJI_INFO = "ℹ️"
EMOJI_QUESTION = "❓"
EMOJI_CONTRACT = "📝"
EMOJI_DOCS = "📄"
EMOJI_MONEY = "💰"
EMOJI_VIDEO = "🎥"
EMOJI_BOOK = "📚"

# ==================== ПОДКЛЮЧЕНИЕ К БД ====================

db_pool = None

async def get_db_connection():
    global db_pool
    if db_pool is None:
        try:
            db_pool = await asyncpg.create_pool(dsn=config.POSTGRES_DSN)
            logger.info("🗄️ Пул соединений с БД создан")
            db_logger.info("Пул соединений инициализирован")
        except Exception as e:
            logger.error(f"❌ Не удалось создать пул БД: {e}", exc_info=True)
            raise
    return db_pool

# ==================== ФУНКЦИИ ВАЛИДАЦИИ ====================

def validate_phone(phone: str) -> str:
    logger.debug(f"Проверка телефона")
    if not phone.startswith('+375') or len(phone) != 13 or not phone[1:].isdigit():
        logger.warning(f"Неверный формат телефона")
        raise ValueError('Телефон должен быть в формате +375XXXXXXXXX')
    return phone

def validate_email(email: str) -> str:
    logger.debug(f"Проверка email")
    try:
        validated = EmailStr._validate(email)
        logger.debug("Email прошёл валидацию")
        return validated
    except ValueError as e:
        logger.warning(f"Неверный формат email")
        raise ValueError('Неверный формат email') from e

def validate_unp(unp: str) -> str:
    logger.debug(f"Проверка УНП")
    if len(unp) != 9 or not unp.isdigit():
        logger.warning(f"Неверный формат УНП")
        raise ValueError('УНП должен состоять из 9 цифр')
    return unp

def validate_okpo(okpo: str) -> str:
    logger.debug(f"Проверка ОКПО")
    if okpo.lower() == '➡️ пропустить':
        return ''
    if len(okpo) != 8 or not okpo.isdigit():
        logger.warning(f"Неверный формат ОКПО")
        raise ValueError('ОКПО должен состоять из 8 цифр или напишите "пропустить"')
    return okpo

def validate_account(account: str) -> str:
    logger.debug(f"Проверка расчётного счёта")
    if not account.startswith('IBAN BY') or len(account) < 16:
        logger.warning(f"Неверный формат расчётного счёта")
        raise ValueError('Расчетный счет должен начинаться с IBAN BY...')
    return account

def validate_passport_date(date_str: str) -> str:
    logger.debug(f"Проверка даты паспорта: {date_str}")
    try:
        datetime.strptime(date_str, "%d.%m.%Y")
        logger.debug("Дата паспорта прошла валидацию")
        return date_str
    except ValueError:
        logger.warning(f"Неверный формат даты паспорта")
        raise ValueError('Неверный формат даты. Используйте ДД.ММ.ГГГГ')

def sanitize_input(text: str) -> str:
    """Очистка ввода от потенциально опасных символов."""
    if not text:
        return text
    
    sanitized = text.replace('\\"', '"').replace("\\'", "'")
    
    if any(char in sanitized for char in [';', '--', '/*', '*/', 'xp_']):
        security_logger.warning(f"Потенциальная SQL-инъекция во вводе: {sanitized[:50]}...")
        logger.warning("Обнаружена попытка SQL-инъекции")
    
    logger.debug(f"Ввод очищен")
    return sanitized

# ==================== PYDANTIC МОДЕЛИ ====================

class PhysicalPersonData(BaseModel):
    full_name: str
    passport_id: str
    passport_issue_date: str
    passport_issued_by: str
    living_address: str
    registration_address: Optional[str] = None
    phone: str
    email: EmailStr

    @field_validator('*')
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        if isinstance(v, str):
            return sanitize_input(v)
        return v

    @field_validator('phone')
    @classmethod
    def phone_validator(cls, v: str) -> str:
        return validate_phone(v)

    @field_validator('email')
    @classmethod
    def email_validator(cls, v: str) -> str:
        return validate_email(v)

    @field_validator('passport_issue_date')
    @classmethod
    def date_validator(cls, v: str) -> str:
        return validate_passport_date(v)

class LegalPersonData(BaseModel):
    organization_name: str
    postal_address: str
    legal_address: Optional[str] = None
    phone: str
    activity_type: str
    okpo: Optional[str] = None
    unp: str
    account_number: str
    bank_name: str
    bank_bic: str
    bank_address: str
    signatory_name: str
    authority_basis: str
    position: str
    email: EmailStr

    @field_validator('*')
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        if isinstance(v, str):
            return sanitize_input(v)
        return v

    @field_validator('account_number')
    @classmethod
    def account_validator(cls, v: str) -> str:
        return validate_account(v)

    @field_validator('unp')
    @classmethod
    def unp_validator(cls, v: str) -> str:
        return validate_unp(v)

    @field_validator('okpo')
    @classmethod
    def okpo_validator(cls, v: str) -> Optional[str]:
        if v is None or v == '':
            return None
        return validate_okpo(v)
		
    @field_validator('email')
    @classmethod
    def email_validator(cls, v: str) -> str:
        return validate_email(v)

# ==================== СОСТОЯНИЯ FSM ====================

class Form(StatesGroup):
    # Физическое лицо
    physical_full_name = State()
    physical_passport_id = State()
    physical_passport_issue_date = State()
    physical_passport_issued_by = State()
    physical_living_address = State()
    physical_registration_address = State()
    physical_phone = State()
    physical_email = State()
    physical_confirm = State()
    
    # Юридическое лицо
    legal_organization_name = State()
    legal_postal_address = State()
    legal_legal_address = State()
    legal_phone = State()
    legal_activity_type = State()
    legal_okpo = State()
    legal_unp = State()
    legal_account_number = State()
    legal_bank_name = State()
    legal_bank_bic = State()
    legal_bank_address = State()
    legal_signatory_name = State()
    legal_authority_basis = State()
    legal_position = State()
    legal_email = State()
    legal_confirm = State()

    # Вопросы
    waiting_for_question = State()
    waiting_for_answer = State()
    
    # Расчёт окупаемости
    roi_fuel_type = State()
    roi_vehicle_weight = State()
    roi_fuel_consumption = State()    
    roi_mileage = State()
    roi_result = State()

class DelayedMessageStates(StatesGroup):
    waiting_for_content = State()
    waiting_for_text = State()
    waiting_for_photo = State()
    waiting_for_time = State()
    waiting_for_recipients = State()
    waiting_for_user_id = State()

class AddNewsStates(StatesGroup):
    waiting_for_title = State()
    waiting_for_text = State()

class AdminStates(StatesGroup):
    waiting_for_moderator_id = State()
    waiting_for_agnks_id = State()
    viewing_actions = State()

class PriceEditStates(StatesGroup):
    waiting_for_price = State()
    price_key = State()

# ==================== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ====================

async def init_db():
    logger.info("🗄️ Инициализация базы данных...")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                username TEXT,
                question TEXT NOT NULL,
                answer TEXT,
                answered_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                answered_at TIMESTAMP,
                skipped_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS questions_user_id_idx ON questions(user_id);
            CREATE INDEX IF NOT EXISTS questions_answered_idx ON questions(answered_at) WHERE answered_at IS NOT NULL;
            """)
            
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS contracts_physical (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                username TEXT,
                full_name TEXT NOT NULL,
                passport_id TEXT NOT NULL,
                passport_issue_date TEXT NOT NULL,
                passport_issued_by TEXT NOT NULL,
                living_address TEXT NOT NULL,
                registration_address TEXT,
                phone TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                is_hidden BOOLEAN DEFAULT FALSE
            );
            CREATE INDEX IF NOT EXISTS contracts_physical_user_id_idx ON contracts_physical(user_id);
            CREATE INDEX IF NOT EXISTS contracts_physical_status_idx ON contracts_physical(status);
            -- индекс на is_hidden будет создан после ALTER TABLE
            """)
            
            # Добавляем недостающие колонки, если их нет (для старых таблиц)
            await conn.execute("""
            ALTER TABLE contracts_physical 
            ADD COLUMN IF NOT EXISTS site_sync_status TEXT DEFAULT 'pending',
            ADD COLUMN IF NOT EXISTS site_contract_id INTEGER,
            ADD COLUMN IF NOT EXISTS is_hidden BOOLEAN DEFAULT FALSE;
            """)
            
            # Создаём индекс на is_hidden после добавления колонки
            await conn.execute("""
            CREATE INDEX IF NOT EXISTS contracts_physical_is_hidden_idx ON contracts_physical(is_hidden);
            """)
            
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS contracts_legal (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                username TEXT,
                organization_name TEXT NOT NULL,
                postal_address TEXT NOT NULL,
                legal_address TEXT,
                phone TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                okpo TEXT,
                unp TEXT NOT NULL,
                account_number TEXT NOT NULL,
                bank_name TEXT NOT NULL,
                bank_bic TEXT NOT NULL,
                bank_address TEXT NOT NULL,
                signatory_name TEXT NOT NULL,
                authority_basis TEXT NOT NULL,
                position TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                is_hidden BOOLEAN DEFAULT FALSE
            );
            CREATE INDEX IF NOT EXISTS contracts_legal_user_id_idx ON contracts_legal(user_id);
            CREATE INDEX IF NOT EXISTS contracts_legal_status_idx ON contracts_legal(status);
            -- индекс на is_hidden будет создан после ALTER TABLE
            """)
            
            await conn.execute("""
            ALTER TABLE contracts_legal 
            ADD COLUMN IF NOT EXISTS site_sync_status TEXT DEFAULT 'pending',
            ADD COLUMN IF NOT EXISTS site_contract_id INTEGER,
            ADD COLUMN IF NOT EXISTS is_hidden BOOLEAN DEFAULT FALSE;
            """)
            
            await conn.execute("""
            CREATE INDEX IF NOT EXISTS contracts_legal_is_hidden_idx ON contracts_legal(is_hidden);
            """)
            
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS bot_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """)
            
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);
            """)
			
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS delayed_messages (
                id SERIAL PRIMARY KEY,
                content_type TEXT NOT NULL,
                text_content TEXT,
                photo_path TEXT,
                send_time TIMESTAMP NOT NULL,
                status TEXT NOT NULL,
                recipient_type TEXT NOT NULL,
                recipient_id BIGINT,
                created_by BIGINT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved_by BIGINT,
				attempts INTEGER DEFAULT 0,
                approved_at TIMESTAMP
            );
            """)
            
            # Таблица для модераторов
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS moderators (
                user_id BIGINT PRIMARY KEY,
                username TEXT,
                added_by BIGINT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
            CREATE INDEX IF NOT EXISTS moderators_user_id_idx ON moderators(user_id);
            """)
            
            # Таблица для AGNKS (переименовано)
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS agnks_users (
                user_id BIGINT PRIMARY KEY,
                username TEXT,
                added_by BIGINT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
            CREATE INDEX IF NOT EXISTS agnks_users_user_id_idx ON agnks_users(user_id);
            """)
            
            # Таблица для логов действий
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_actions (
                id SERIAL PRIMARY KEY,
                admin_id BIGINT NOT NULL,
                action TEXT NOT NULL,
                target_id BIGINT,
                target_username TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS admin_actions_admin_id_idx ON admin_actions(admin_id);
            CREATE INDEX IF NOT EXISTS admin_actions_created_at_idx ON admin_actions(created_at);
            """)
            
            # Таблица для логирования публикаций новостей
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS news_publications (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                username TEXT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                site_news_id INTEGER,
                status TEXT NOT NULL,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                published_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS news_publications_user_id_idx ON news_publications(user_id);
            CREATE INDEX IF NOT EXISTS news_publications_status_idx ON news_publications(status);
            """)
            
            # Добавляем начальные настройки
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('welcome_message', 'Добро пожаловать в бот METAN.BY!')
            ON CONFLICT (key) DO NOTHING
            """)
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('button_unanswered_questions', '1'),
                ('button_view_contracts', '1'),
                ('button_delayed_messages', '1'),
                ('button_add_news', '1')
            ON CONFLICT (key) DO NOTHING
            """)
            
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('gasoline_price', '2.5'),
                ('diesel_price', '2.46'),
                ('cng_price', '1.0'),
                ('gasoline_installation_light', '3000'),
                ('gasoline_installation_heavy', '5000'),
                ('diesel_installation', '15000')
            ON CONFLICT (key) DO NOTHING
             """)            
			
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('notify_admin_questions', '1'),
                ('notify_admin_contracts', '1'),
                ('notify_admin_errors', '1'),
                ('notify_admin_news', '1'),
                ('notify_moderators_questions', '1'),
                ('notify_moderators_contracts', '1'),
                ('notify_moderators_news', '1')
            ON CONFLICT (key) DO NOTHING
            """)
            
            # Новые настройки для модераторов
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('notify_moderators_news_from_admin', '1'),
                ('notify_moderators_news_from_agnks', '1')
            ON CONFLICT (key) DO NOTHING
            """)
            
            # Настройки уведомлений для AGNKS (убрана общая, оставлены раздельные)
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('notify_agnks_news_from_admin', '1'),
                ('notify_agnks_news_from_agnks', '1')
            ON CONFLICT (key) DO NOTHING
            """)
            
            # Новая настройка: публикация новостей в Telegram-группу
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('button_publish_to_group', '1')
            ON CONFLICT (key) DO NOTHING
            """)
            
            logger.info("✅ База данных инициализирована успешно")
            db_logger.info("Схема БД создана/обновлена")
    except Exception as e:
        logger.error(f"❌ Ошибка инициализации базы данных: {e}", exc_info=True)
        raise

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

async def get_fuel_price(fuel_type: str) -> float:
    key = 'gasoline_price' if fuel_type == 'Бензин' else 'diesel_price'
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT value FROM bot_settings WHERE key = $1",
                key
            )
            return float(result) if result else (2.5 if fuel_type == 'Бензин' else 2.46)
    except Exception as e:
        logger.error(f"Не удалось получить цену для {fuel_type}: {e}")
        return 2.5 if fuel_type == 'Бензин' else 2.46

async def get_cng_price() -> float:
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT value FROM bot_settings WHERE key = 'cng_price'"
            )
            return float(result) if result else 1.0
    except Exception as e:
        logger.error(f"Не удалось получить цену КПГ: {e}")
        return 1.0

async def get_installation_cost(fuel_type: str, weight: str = None) -> float:
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            if fuel_type == 'Бензин':
                key = 'gasoline_installation_light' if weight == 'До 3,5 тонн' else 'gasoline_installation_heavy'
            else:
                key = 'diesel_installation'
            
            result = await conn.fetchval(
                "SELECT value FROM bot_settings WHERE key = $1",
                key
            )
            if result:
                return float(result)
            else:
                if fuel_type == 'Бензин':
                    return 3000 if weight == 'До 3,5 тонн' else 5000
                else:
                    return 15000
    except Exception as e:
        logger.error(f"Не удалось получить стоимость переоборудования: {e}")
        if fuel_type == 'Бензин':
            return 3000 if weight == 'До 3,5 тонн' else 5000
        else:
            return 15000

async def rotate_backups(keep_last: int = 5):
    """Оставляет только последние N бэкапов"""
    try:
        if not os.path.exists("backups"):
            return 0
        
        backups = []
        for f in os.listdir("backups"):
            if f.startswith("backup_") and (f.endswith(".sql") or f.endswith(".sql.gz")):
                filepath = os.path.join("backups", f)
                backups.append((filepath, os.path.getmtime(filepath)))
        
        backups.sort(key=lambda x: x[1], reverse=True)
        
        removed = 0
        for filepath, _ in backups[keep_last:]:
            os.remove(filepath)
            removed += 1
            logger.info(f"🗑️ Удалён старый бэкап: {os.path.basename(filepath)}")
        
        if removed > 0:
            logger.info(f"🔄 Авторотация: удалено {removed} старых бэкапов, оставлено {keep_last}")
        
        return removed
    except Exception as e:
        logger.error(f"Ошибка при ротации бэкапов: {e}", exc_info=True)
        return 0

async def create_db_backup():
    """Создание бэкапа с автоочисткой старых"""
    logger.info("📀 Создание резервной копии базы данных")
    try:
        if not await check_disk_space():
            logger.error("❌ Недостаточно места на диске для резервной копии")
            return False
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{timestamp}.sql"
        backup_path = f"backups/{backup_filename}"
        
        dsn = config.POSTGRES_DSN
        proc = await asyncio.create_subprocess_exec(
            "pg_dump", dsn,
            "-f", backup_path,
            "--clean",
            "--if-exists",
            stderr=asyncio.subprocess.PIPE
        )
        
        _, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            logger.error(f"❌ Ошибка pg_dump: {stderr.decode()}")
            return False
        
        # Сжимаем бэкап
        with open(backup_path, 'rb') as f_in:
            with gzip.open(f"{backup_path}.gz", 'wb') as f_out:
                f_out.write(f_in.read())
        os.remove(backup_path)
        backup_path = f"{backup_path}.gz"
        
        file_size = os.path.getsize(backup_path) / (1024 * 1024)
        logger.info(f"✅ Бэкап создан: {backup_filename}.gz ({file_size:.2f} MB)")
        
        # Автоматическая ротация
        removed = await rotate_backups(5)
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Ошибка бэкапа: {e}", exc_info=True)
        return False

async def is_admin(user_id: int) -> bool:
    result = user_id in config.ADMIN_IDS
    logger.debug(f"Проверка администратора для {user_id}: {result}")
    return result

async def get_moderators(active_only: bool = True) -> List[Dict]:
    """Получить список модераторов из БД"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        if active_only:
            rows = await conn.fetch("SELECT * FROM moderators WHERE is_active = TRUE ORDER BY added_at")
        else:
            rows = await conn.fetch("SELECT * FROM moderators ORDER BY added_at")
        return [dict(row) for row in rows]

async def get_agnks_users(active_only: bool = True) -> List[Dict]:
    """Получить список AGNKS пользователей из БД"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        if active_only:
            rows = await conn.fetch("SELECT * FROM agnks_users WHERE is_active = TRUE ORDER BY added_at")
        else:
            rows = await conn.fetch("SELECT * FROM agnks_users ORDER BY added_at")
        return [dict(row) for row in rows]

async def add_moderator(user_id: int, username: str = None, admin_id: int = None) -> bool:
    """Добавить модератора"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        try:
            await conn.execute("""
                INSERT INTO moderators (user_id, username, added_by) 
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id) DO UPDATE SET 
                    is_active = TRUE,
                    username = EXCLUDED.username,
                    added_by = EXCLUDED.added_by,
                    added_at = CURRENT_TIMESTAMP
                """,
                user_id, username, admin_id
            )
            
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, target_username, details)
                VALUES ($1, $2, $3, $4, $5)
                """,
                admin_id, 'add_moderator', user_id, username, f'Добавлен модератор {username or user_id}'
            )
            
            logger.info(f"➕ Модератор {user_id} добавлен")
            return True
        except Exception as e:
            logger.error(f"Ошибка добавления модератора: {e}")
            return False

async def remove_moderator(user_id: int, admin_id: int = None) -> bool:
    """Удалить модератора (мягкое удаление)"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        try:
            await conn.execute(
                "UPDATE moderators SET is_active = FALSE WHERE user_id = $1",
                user_id
            )
            
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, details)
                VALUES ($1, $2, $3, $4)
                """,
                admin_id, 'remove_moderator', user_id, f'Удалён модератор {user_id}'
            )
            
            logger.info(f"➖ Модератор {user_id} удалён")
            return True
        except Exception as e:
            logger.error(f"Ошибка удаления модератора: {e}")
            return False

async def add_agnks_user(user_id: int, username: str = None, admin_id: int = None) -> bool:
    """Добавить AGNKS пользователя"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        try:
            await conn.execute("""
                INSERT INTO agnks_users (user_id, username, added_by) 
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id) DO UPDATE SET 
                    is_active = TRUE,
                    username = EXCLUDED.username,
                    added_by = EXCLUDED.added_by,
                    added_at = CURRENT_TIMESTAMP
                """,
                user_id, username, admin_id
            )
            
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, target_username, details)
                VALUES ($1, $2, $3, $4, $5)
                """,
                admin_id, 'add_agnks', user_id, username, f'Добавлен AGNKS {username or user_id}'
            )
            
            logger.info(f"➕ AGNKS {user_id} добавлен")
            return True
        except Exception as e:
            logger.error(f"Ошибка добавления AGNKS: {e}")
            return False

async def remove_agnks_user(user_id: int, admin_id: int = None) -> bool:
    """Удалить AGNKS пользователя"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        try:
            await conn.execute(
                "UPDATE agnks_users SET is_active = FALSE WHERE user_id = $1",
                user_id
            )
            
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, details)
                VALUES ($1, $2, $3, $4)
                """,
                admin_id, 'remove_agnks', user_id, f'Удалён AGNKS {user_id}'
            )
            
            logger.info(f"➖ AGNKS {user_id} удалён")
            return True
        except Exception as e:
            logger.error(f"Ошибка удаления AGNKS: {e}")
            return False

async def is_moderator(user_id: int) -> bool:
    if user_id in config.ADMIN_IDS:
        return True
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        result = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM moderators WHERE user_id = $1 AND is_active = TRUE)",
            user_id
        )
        return result or False

async def is_agnks(user_id: int) -> bool:
    if user_id in config.ADMIN_IDS:
        return True
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        result = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM agnks_users WHERE user_id = $1 AND is_active = TRUE)",
            user_id
        )
        return result or False

async def is_button_enabled(button_key: str) -> bool:
    logger.debug(f"Проверка состояния кнопки {button_key}")
    cached = redis_client.get(f"button:{button_key}")
    if cached is not None:
        logger.debug(f"Кнопка {button_key} из кэша: {cached == '1'}")
        return cached == "1"
    
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            result = await conn.fetchrow(
                "SELECT value FROM bot_settings WHERE key = $1",
                button_key
            )
            enabled = result and result['value'] == '1' if result else True
            logger.debug(f"Кнопка {button_key} из БД: {enabled}")
        
        redis_client.setex(f"button:{button_key}", 300, "1" if enabled else "0")
        return enabled
    except Exception as e:
        logger.error(f"Не удалось проверить состояние кнопки {button_key}: {e}", exc_info=True)
        return True

async def notify_admins(text: str, emoji: str = EMOJI_INFO, notification_type: str = "info", reply_markup=None):
    """Отправка уведомлений всем администраторам с проверкой настроек"""
    try:
        if notification_type == "question" and not await is_notification_enabled('notify_admin_questions'):
            logger.info("Уведомления о вопросах для админов отключены")
            return
        if notification_type == "contract" and not await is_notification_enabled('notify_admin_contracts'):
            logger.info("Уведомления о договорах для админов отключены")
            return
        if notification_type == "error" and not await is_notification_enabled('notify_admin_errors'):
            logger.info("Уведомления об ошибках для админов отключены")
            return
        if notification_type == "news" and not await is_notification_enabled('notify_admin_news'):
            logger.info("Уведомления о новостях для админов отключены")
            return

        tasks = []
        for admin_id in config.ADMIN_IDS:
            tasks.append(bot.send_message(admin_id, f"{emoji} {text}", reply_markup=reply_markup))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info(f"📢 Уведомление отправлено админам ({notification_type})")
    except Exception as e:
        logger.error(f"Ошибка уведомления админов: {e}", exc_info=True)

async def notify_moderators(text: str, emoji: str = EMOJI_INFO, notification_type: str = "info", reply_markup=None, author_is_admin: bool = False, exclude_user_id: Optional[int] = None):
    """
    Отправка уведомлений модераторам с проверкой настроек.
    Для новостей нужно передать author_is_admin, чтобы выбрать правильную настройку.
    Можно исключить одного пользователя (exclude_user_id).
    """
    # Для новостей проверяем раздельные настройки
    if notification_type == "news":
        if author_is_admin:
            if not await is_notification_enabled('notify_moderators_news_from_admin'):
                logger.info("Уведомления о новостях от администратора для модераторов отключены")
                return
        else:
            if not await is_notification_enabled('notify_moderators_news_from_agnks'):
                logger.info("Уведомления о новостях от AGNKS для модераторов отключены")
                return
    else:
        # Для других типов используем старые настройки
        if notification_type == "question" and not await is_notification_enabled('notify_moderators_questions'):
            logger.info("Уведомления о вопросах для модераторов отключены")
            return
        if notification_type == "contract" and not await is_notification_enabled('notify_moderators_contracts'):
            logger.info("Уведомления о договорах для модераторов отключены")
            return
        # Если это другой тип, используем общую настройку (но её нет, поэтому разрешаем)

    # Получаем активных модераторов из БД
    moderators = await get_moderators(active_only=True)
    if not moderators:
        logger.debug("Нет активных модераторов для уведомления")
        return

    tasks = []
    for mod in moderators:
        mod_id = mod['user_id']
        if exclude_user_id is not None and mod_id == exclude_user_id:
            continue  # пропускаем исключённого пользователя
        try:
            tasks.append(bot.send_message(mod_id, f"{emoji} {text}", reply_markup=reply_markup))
            logger.debug(f"Уведомление отправлено модератору {mod_id}")
        except Exception as e:
            logger.error(f"Ошибка уведомления модератора {mod_id}: {e}")
    
    await asyncio.gather(*tasks, return_exceptions=True)

async def notify_agnks(text: str, emoji: str = EMOJI_INFO, notification_type: str = "info", author_is_agnks: bool = False, exclude_user_id: Optional[int] = None):
    """
    Отправка уведомлений пользователям AGNKS.
    Для новостей передаём author_is_agnks, чтобы выбрать нужную настройку.
    Можно исключить одного пользователя (exclude_user_id).
    """
    if notification_type == "news":
        if author_is_agnks:
            if not await is_notification_enabled('notify_agnks_news_from_agnks'):
                logger.info("Уведомления о новостях от AGNKS для AGNKS отключены")
                return
        else:
            if not await is_notification_enabled('notify_agnks_news_from_admin'):
                logger.info("Уведомления о новостях от администратора для AGNKS отключены")
                return
    else:
        # Другие типы уведомлений для AGNKS пока не поддерживаются, но можно расширить
        pass

    agnks_users = await get_agnks_users(active_only=True)
    if not agnks_users:
        logger.debug("Нет активных пользователей AGNKS для уведомления")
        return

    tasks = []
    for user in agnks_users:
        user_id = user['user_id']
        if exclude_user_id is not None and user_id == exclude_user_id:
            continue
        try:
            tasks.append(bot.send_message(user_id, f"{emoji} {text}"))
            logger.debug(f"Уведомление отправлено AGNKS {user_id}")
        except Exception as e:
            logger.error(f"Ошибка уведомления AGNKS {user_id}: {e}")
    
    await asyncio.gather(*tasks, return_exceptions=True)

async def is_notification_enabled(setting_key: str) -> bool:
    logger.debug(f"Проверка состояния уведомления {setting_key}")
    cached = redis_client.get(f"notification:{setting_key}")
    if cached is not None:
        logger.debug(f"Уведомление {setting_key} из кэша: {cached == '1'}")
        return cached == "1"
    
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            result = await conn.fetchrow(
                "SELECT value FROM bot_settings WHERE key = $1",
                setting_key
            )
            enabled = result and result['value'] == '1' if result else True
            logger.debug(f"Уведомление {setting_key} из БД: {enabled}")
        
        redis_client.setex(f"notification:{setting_key}", 300, "1" if enabled else "0")
        return enabled
    except Exception as e:
        logger.error(f"Не удалось проверить состояние уведомления {setting_key}: {e}", exc_info=True)
        return True

async def get_user_mention(user: types.User, markdown: bool = False) -> str:
    """Возвращает упоминание пользователя. Если markdown=True, то с markdown-ссылкой, иначе plain text."""
    if markdown:
        return f"@{user.username}" if user.username else f"[{user.full_name}](ID: {user.id})"
    else:
        return f"@{user.username}" if user.username else f"{user.full_name} (ID: {user.id})"

async def get_user_mention_plain(user: types.User) -> str:
    """Возвращает упоминание пользователя в plain text."""
    return f"@{user.username}" if user.username else f"{user.full_name} (ID: {user.id})"

async def export_to_csv(data: List[Dict], filename: str) -> Optional[str]:
    logger.info(f"📊 Экспорт данных в CSV: {filename}")
    try:
        csv_path = f"temp/{filename}"
        os.makedirs("temp", exist_ok=True)
        
        if not data:
            logger.warning(f"Нет данных для экспорта {filename}")
            return None
        
        keys = data[0].keys()
        
        # Используем utf-8-sig для корректного отображения в Excel
        with open(csv_path, mode='w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        
        if not os.path.exists(csv_path):
            logger.error(f"Не удалось создать файл: {csv_path}")
            return None
            
        logger.info(f"✅ Экспорт в CSV успешен: {csv_path}")
        return csv_path
    except Exception as e:
        logger.error(f"Ошибка экспорта в CSV: {e}", exc_info=True)
        return None

async def cleanup_temp_files():
    """Очистка временных файлов"""
    logger.info("🧹 Очистка временных файлов")
    try:
        if os.path.exists("temp"):
            total_size = 0
            deleted = 0
            for filename in os.listdir("temp"):
                file_path = os.path.join("temp", filename)
                try:
                    if os.path.isfile(file_path):
                        file_size = os.path.getsize(file_path)
                        total_size += file_size
                        os.unlink(file_path)
                        deleted += 1
                        logger.debug(f"Удалён: {filename} ({file_size/1024:.1f} KB)")
                except Exception as e:
                    logger.error(f"Не удалось удалить {file_path}: {e}")
            
            logger.info(f"✅ Очищено {deleted} файлов, всего {total_size/1024/1024:.2f} MB")
        return True
    except Exception as e:
        logger.error(f"Ошибка очистки: {e}", exc_info=True)
        return False

async def check_disk_space() -> bool:
    logger.debug("Проверка места на диске")
    try:
        if hasattr(os, 'statvfs'):
            stat = os.statvfs('/')
            free_space_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
        else:
            usage = shutil.disk_usage('C:\\')
            free_space_gb = usage.free / (1024 ** 3)
        
        MINIMUM_SPACE_GB = 1
        if free_space_gb < MINIMUM_SPACE_GB:
            logger.warning(f"⚠️ Мало места на диске: {free_space_gb:.2f}GB")
            return False
        logger.debug(f"Места достаточно: {free_space_gb:.2f}GB свободно")
        return True
    except Exception as e:
        logger.error(f"Ошибка проверки места на диске: {e}", exc_info=True)
        return False

async def send_document_safe(message: types.Message, file_path: str, filename: str):
    logger.info(f"📎 Отправка документа: {filename}")
    try:
        file_size = os.path.getsize(file_path) / (1024 * 1024)
        if file_size > 50:
            logger.warning(f"Файл слишком большой: {file_size:.2f}MB")
            await message.answer(f"Файл {filename} слишком большой ({file_size:.2f}MB). Максимальный размер: 50MB")
            return
        
        with open(file_path, 'rb') as file:
            await message.answer_document(
                BufferedInputFile(file.read(), filename=filename))
        logger.info("✅ Документ отправлен успешно")
    except Exception as e:
        logger.error(f"Не удалось отправить документ {filename}: {e}", exc_info=True)
        await message.answer(f"Ошибка при отправке файла {filename}: {str(e)}")

async def export_questions_to_csv() -> Optional[str]:
    logger.info("📊 Экспорт вопросов в CSV")
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            questions = await conn.fetch(
                "SELECT id, user_id, username, question, answer, answered_by, created_at, answered_at, skipped_at FROM questions"
            )
            
            if not questions:
                logger.warning("Нет вопросов для экспорта")
                return None
            
            questions_data = []
            for q in questions:
                questions_data.append({
                    "id": q['id'],
                    "user_id": q['user_id'],
                    "username": q['username'] or "",
                    "question": q['question'],
                    "answer": q['answer'] or "",
                    "answered_by": q['answered_by'] or "",
                    "created_at": q['created_at'],
                    "answered_at": q['answered_at'] or "",
                    "skipped_at": q['skipped_at'] or ""
                })
            
            return await export_to_csv(questions_data, "questions.csv")
    except Exception as e:
        logger.error(f"Не удалось экспортировать вопросы: {e}", exc_info=True)
        return None

async def export_physical_contracts_to_csv() -> Optional[str]:
    logger.info("📊 Экспорт договоров физ. лиц в CSV")
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            contracts = await conn.fetch("SELECT * FROM contracts_physical")
            
            if not contracts:
                logger.warning("Нет договоров физ. лиц для экспорта")
                return None
            
            contracts_data = []
            for c in contracts:
                contracts_data.append({
                    'id': c['id'],
                    'user_id': c['user_id'],
                    'username': c['username'],
                    'full_name': c['full_name'],
                    'passport_id': decrypt_data(c['passport_id']),
                    'passport_issue_date': c['passport_issue_date'],
                    'passport_issued_by': c['passport_issued_by'],
                    'living_address': c['living_address'],
                    'registration_address': c['registration_address'],
                    'phone': decrypt_data(c['phone']),
                    'email': c['email'],
                    'created_at': c['created_at'],
                    'status': c['status'],
                    'is_hidden': c.get('is_hidden', False),
                    'site_sync_status': c.get('site_sync_status', 'pending'),
                    'site_contract_id': c.get('site_contract_id')
                })
            
            return await export_to_csv(contracts_data, "physical_contracts.csv")
    except Exception as e:
        logger.error(f"Не удалось экспортировать договоры физ. лиц: {e}", exc_info=True)
        return None

async def export_legal_contracts_to_csv() -> Optional[str]:
    logger.info("📊 Экспорт договоров юр. лиц в CSV")
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            contracts = await conn.fetch("SELECT * FROM contracts_legal")
            
            if not contracts:
                logger.warning("Нет договоров юр. лиц для экспорта")
                return None
            
            contracts_data = []
            for c in contracts:
                try:
                    contract_data = {
                        'id': c['id'],
                        'user_id': c['user_id'],
                        'username': c['username'],
                        'organization_name': c['organization_name'],
                        'postal_address': c['postal_address'],
                        'legal_address': c['legal_address'],
                        'phone': None,
                        'activity_type': c['activity_type'],
                        'okpo': None,
                        'unp': None,
                        'account_number': None,
                        'bank_name': c['bank_name'],
                        'bank_bic': c['bank_bic'],
                        'bank_address': c['bank_address'],
                        'signatory_name': c['signatory_name'],
                        'authority_basis': c['authority_basis'],
                        'position': c['position'],
                        'email': c['email'],
                        'created_at': c['created_at'],
                        'status': c['status'],
                        'is_hidden': c.get('is_hidden', False),
                        'site_sync_status': c.get('site_sync_status', 'pending'),
                        'site_contract_id': c.get('site_contract_id')
                    }
                    
                    try:
                        if c['phone']:
                            contract_data['phone'] = decrypt_data(c['phone'])
                    except Exception as e:
                        logger.error(f"Не удалось расшифровать телефон для договора {c['id']}: {e}")
                        contract_data['phone'] = "[ошибка расшифровки]"
                    
                    try:
                        if c['okpo']:
                            contract_data['okpo'] = decrypt_data(c['okpo'])
                    except Exception as e:
                        logger.error(f"Не удалось расшифровать ОКПО для договора {c['id']}: {e}")
                        contract_data['okpo'] = "[ошибка расшифровки]"
                    
                    try:
                        if c['unp']:
                            contract_data['unp'] = decrypt_data(c['unp'])
                    except Exception as e:
                        logger.error(f"Не удалось расшифровать УНП для договора {c['id']}: {e}")
                        contract_data['unp'] = "[ошибка расшифровки]"
                    
                    try:
                        if c['account_number']:
                            contract_data['account_number'] = decrypt_data(c['account_number'])
                    except Exception as e:
                        logger.error(f"Не удалось расшифровать номер счёта для договора {c['id']}: {e}")
                        contract_data['account_number'] = "[ошибка расшифровки]"
                    
                    contracts_data.append(contract_data)
                    
                except Exception as e:
                    logger.error(f"Не удалось обработать договор {c['id']}: {e}")
                    continue
            
            if not contracts_data:
                logger.warning("Нет валидных договоров для экспорта после обработки")
                return None
            
            return await export_to_csv(contracts_data, "legal_contracts.csv")
            
    except Exception as e:
        logger.error(f"Не удалось экспортировать договоры юр. лиц: {e}", exc_info=True)
        return None

async def get_all_users_count() -> int:
    logger.debug("Получение количества пользователей")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            result = await conn.fetchval("SELECT COUNT(*) FROM users")
            return result if result else 0
    except Exception as e:
        logger.error(f"Не удалось получить количество пользователей: {e}", exc_info=True)
        return 0

async def register_user(user: types.User):
    logger.info(f"📝 Регистрация пользователя {user.id}")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO users (user_id, username, first_name, last_name) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO NOTHING",
                user.id, user.username, user.first_name, user.last_name
            )
            await conn.execute(
                "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE user_id = $1",
                user.id
            )
        logger.info(f"✅ Пользователь {user.id} зарегистрирован/обновлён")
    except Exception as e:
        logger.error(f"Не удалось зарегистрировать пользователя {user.id}: {e}", exc_info=True)
        raise

async def update_user_activity(user_id: int):
    """Обновляет время последней активности пользователя (fire-and-forget)"""
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE user_id = $1",
                user_id
            )
    except Exception as e:
        logger.error(f"Ошибка обновления last_activity для {user_id}: {e}")

# ==================== ПОСТРОИТЕЛИ КЛАВИАТУР ====================

async def get_main_menu(user_id: int) -> types.ReplyKeyboardMarkup:
    logger.debug(f"Генерация главного меню для пользователя {user_id}")
    builder = ReplyKeyboardBuilder()
    
    if await is_button_enabled('button_consultation'):
        builder.button(text=f"{EMOJI_QUESTION} Консультация со специалистом")
    
    if await is_button_enabled('button_roi'):
        builder.button(text=f"{EMOJI_MONEY} Расчёт окупаемости")
    
    if await is_button_enabled('button_experience'):
        builder.button(text=f"{EMOJI_VIDEO}{EMOJI_BOOK}Полезная информация")
    
    if await is_button_enabled('button_contract'):
        builder.button(text=f"{EMOJI_CONTRACT} Заключение договора")
    
    if await is_agnks(user_id) and await is_button_enabled('button_add_news'):
        builder.button(text="📰 Добавить новость на сайт")
    
    if await is_moderator(user_id):
        builder.button(text="🔧 Модераторское меню")
    
    if await is_admin(user_id):
        builder.button(text="👑 Админ-панель")
    
    builder.adjust(2, 2, 1, 2, 1)
    return builder.as_markup(resize_keyboard=True)

async def get_experience_menu() -> types.InlineKeyboardMarkup:
    logger.debug("Генерация меню полезной информации")
    builder = InlineKeyboardBuilder()
    builder.button(text=f"{EMOJI_VIDEO} Видеоматериалы", callback_data="experience_video")
    builder.button(text=f"{EMOJI_BOOK} Печатные издания", callback_data="experience_print")
    builder.button(text="⬅️ Назад", callback_data="main_menu")
    builder.adjust(2, 1)
    return builder.as_markup()

async def get_contract_type_menu() -> types.InlineKeyboardMarkup:
    logger.debug("Генерация меню выбора типа договора")
    builder = InlineKeyboardBuilder()
    builder.button(text="Физическое лицо", callback_data="contract_physical")
    builder.button(text="Юридическое лицо", callback_data="contract_legal")
    builder.button(text="⬅️ Назад", callback_data="main_menu")
    builder.adjust(2, 1)
    return builder.as_markup()

async def get_cancel_keyboard() -> types.ReplyKeyboardMarkup:
    logger.debug("Генерация клавиатуры отмены")
    builder = ReplyKeyboardBuilder()
    builder.button(text="❌ Отменить заполнение")
    return builder.as_markup(resize_keyboard=True)

async def get_moderator_menu() -> types.ReplyKeyboardMarkup:
    builder = ReplyKeyboardBuilder()
    
    if await is_button_enabled('button_unanswered_questions'):
        builder.button(text="📋 Неотвеченные вопросы")
    
    if await is_button_enabled('button_view_contracts'):
        builder.button(text="📝 Просмотреть договоры")
    
    if await is_button_enabled('button_delayed_messages'):
        builder.button(text="⏱ Создать отложенное сообщение")
    
    builder.button(text="⬅️ Главное меню")
    builder.adjust(2, 1, 1)
    return builder.as_markup(resize_keyboard=True)

async def get_admin_menu() -> types.ReplyKeyboardMarkup:
    builder = ReplyKeyboardBuilder()
    builder.button(text="📊 Статистика")
    builder.button(text="📁 Экспорт данных")
    builder.button(text="🗃 Управление хранилищем")
    builder.button(text="🔔 Управление уведомлениями")
    builder.button(text="🛠 Управление кнопками")
    builder.button(text="⏱ Управление отлож. сообщениями")
    builder.button(text="⛽ Управление ценами")
    builder.button(text="👥 Управление персоналом")
    builder.button(text="⬅️ Главное меню")
    builder.adjust(3, 3, 2, 1, 1)
    return builder.as_markup(resize_keyboard=True)

async def get_question_action_menu(question_id: int, has_next: bool = False, has_prev: bool = False) -> types.InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="💪🏾 Ответить", callback_data=f"answer_{question_id}")
    builder.button(text="🙈 Пропустить", callback_data=f"skip_{question_id}")
    
    if has_prev:
        builder.button(text="⬅️ Предыдущий", callback_data=f"prev_question_{question_id}")
    if has_next:
        builder.button(text="➡️ Следующий", callback_data=f"next_question_{question_id}")
    
    builder.button(text="👀 Скрыть", callback_data="cancel_question")
    builder.adjust(2, 2, 1)
    return builder.as_markup()

async def get_confirm_menu(confirm_data: str) -> types.InlineKeyboardMarkup:
    logger.debug(f"Генерация меню подтверждения для {confirm_data}")
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Подтвердить", callback_data=f"confirm_{confirm_data}")
    builder.button(text="❌ Отменить", callback_data="cancel_confirm")
    return builder.as_markup()

async def get_cancel_reply_keyboard() -> types.ReplyKeyboardMarkup:
    logger.debug("Генерация клавиатуры отмены ответа")
    builder = ReplyKeyboardBuilder()
    builder.button(text="❌ Отменить ответ")
    return builder.as_markup(resize_keyboard=True)

# ==================== НОВАЯ КЛАВИАТУРА ДЛЯ ДОГОВОРОВ ====================

async def get_contract_action_menu(contract_id: int, contract_type: str, has_next: bool = False, has_prev: bool = False, total_count: int = 1) -> types.InlineKeyboardMarkup:
    """Генерация меню действий для договора"""
    logger.debug(f"Генерация меню действий для договора {contract_type} {contract_id}")
    builder = InlineKeyboardBuilder()
    
    # Кнопка удаления (только из списка, не из БД)
    builder.button(text="🗑️ Удалить из списка", callback_data=f"hide_contract:{contract_type}:{contract_id}")
    
    # Кнопка "Удалить все" (если договоров больше одного)
    if total_count > 1:
        builder.button(text="🗑️ Удалить все", callback_data=f"hide_all_{contract_type}")
    
    # Навигация
    if has_prev:
        builder.button(text="⬅️ Предыдущий", callback_data=f"prev_contract:{contract_type}:{contract_id}")
    if has_next:
        builder.button(text="➡️ Следующий", callback_data=f"next_contract:{contract_type}:{contract_id}")
    
    # Кнопка возврата в меню
    builder.button(text="◀️ Назад в меню", callback_data="moderator_back")
    
    # Распределяем кнопки
    buttons_count = 1 + (1 if total_count > 1 else 0)  # удалить + удалить все (если есть)
    if has_prev or has_next:
        builder.adjust(buttons_count, 2, 1)  # первый ряд: кнопки удаления, второй: навигация, третий: назад
    else:
        builder.adjust(buttons_count, 1)  # если нет навигации, то два ряда: удаление и назад
    
    return builder.as_markup()

# ==================== ФУНКЦИИ ДЛЯ РАБОТЫ СО СПИСКОМ ДОГОВОРОВ ====================

async def hide_contract_from_list(contract_id: int, contract_type: str, moderator_id: int) -> bool:
    """Помечает договор как скрытый (не удаляет из БД)"""
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            table = "contracts_physical" if contract_type == "physical" else "contracts_legal"
            
            # Получаем информацию о договоре для лога
            contract = await conn.fetchrow(f"SELECT user_id, username FROM {table} WHERE id = $1", contract_id)
            
            if not contract:
                logger.warning(f"Договор {contract_type} ID {contract_id} не найден для скрытия")
                return False
            
            # Помечаем договор как скрытый
            await conn.execute(f"UPDATE {table} SET is_hidden = TRUE WHERE id = $1", contract_id)
            
            # Логируем действие
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, details)
                VALUES ($1, $2, $3, $4)
                """,
                moderator_id, f'hide_{contract_type}_contract', contract_id,
                f'Скрыт договор {contract_type} ID {contract_id} из списка (пользователь: {contract["user_id"]})'
            )
            
            logger.info(f"👁️ Модератор {moderator_id} скрыл договор {contract_type} ID {contract_id} из списка")
            return True
            
    except Exception as e:
        logger.error(f"Ошибка при скрытии договора {contract_type} ID {contract_id}: {e}", exc_info=True)
        return False

async def hide_all_contracts_from_list(contract_type: str, moderator_id: int) -> int:
    """Помечает все договоры как скрытые (не удаляет из БД)"""
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            table = "contracts_physical" if contract_type == "physical" else "contracts_legal"
            
            # Получаем количество для скрытия
            count = await conn.fetchval(f"SELECT COUNT(*) FROM {table} WHERE status = 'pending' AND is_hidden = FALSE")
            
            if count == 0:
                return 0
            
            # Помечаем все договоры со статусом pending как скрытые
            await conn.execute(f"UPDATE {table} SET is_hidden = TRUE WHERE status = 'pending'")
            
            # Логируем действие
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, details)
                VALUES ($1, $2, $3)
                """,
                moderator_id, f'hide_all_{contract_type}_contracts',
                f'Скрыты все договоры {contract_type} в статусе pending из списка (всего: {count})'
            )
            
            logger.info(f"👁️ Модератор {moderator_id} скрыл все договоры {contract_type} из списка (всего: {count})")
            return count
            
    except Exception as e:
        logger.error(f"Ошибка при скрытии всех договоров {contract_type}: {e}", exc_info=True)
        return 0

# ==================== ОБРАБОТЧИКИ ПРОСМОТРА ДОГОВОРОВ ====================

@dp.message(F.text == "📝 Просмотреть договоры")
async def view_contracts_handler(message: types.Message):
    if not await is_moderator(message.from_user.id):
        return
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            physical_count = await conn.fetchval(
                "SELECT COUNT(*) FROM contracts_physical WHERE status = 'pending' AND is_hidden = FALSE"
            )
            legal_count = await conn.fetchval(
                "SELECT COUNT(*) FROM contracts_legal WHERE status = 'pending' AND is_hidden = FALSE"
            )
            
            if physical_count == 0 and legal_count == 0:
                await message.answer("Нет договоров для обработки.", reply_markup=await get_moderator_menu())
                return
                
            text = "Выберите тип договоров для обработки:\n\n"
            if physical_count > 0:
                text += f"📋 Физические лица: {physical_count} на обработку\n"
            if legal_count > 0:
                text += f"📋 Юридические лица: {legal_count} на обработку"
            
            builder = InlineKeyboardBuilder()
            if physical_count > 0:
                builder.button(text="Физические лица", callback_data="view_physical")
            if legal_count > 0:
                builder.button(text="Юридические лица", callback_data="view_legal")
            builder.button(text="⬅️ Назад", callback_data="moderator_back")
            builder.adjust(2, 1)
            
            await message.answer(
                text,
                reply_markup=builder.as_markup()
            )
            
    except Exception as e:
        logger.error(f"Не удалось получить количество договоров: {e}", exc_info=True)
        await message.answer("Произошла ошибка при получении списка договоров.")

@dp.callback_query(F.data == "view_physical")
async def view_physical_contracts_handler(callback: types.CallbackQuery):
    logger.info(f"Модератор {callback.from_user.id} просматривает договоры физ. лиц")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Получаем общее количество
            total_count = await conn.fetchval(
                "SELECT COUNT(*) FROM contracts_physical WHERE status = 'pending' AND is_hidden = FALSE"
            )
            
            if total_count == 0:
                await callback.message.edit_text(
                    "Нет договоров физ. лиц для обработки.",
                    reply_markup=None
                )
                await callback.message.answer(
                    "Модераторское меню:",
                    reply_markup=await get_moderator_menu()
                )
                return
            
            # Получаем первый договор
            contract = await conn.fetchrow(
                "SELECT * FROM contracts_physical WHERE status = 'pending' AND is_hidden = FALSE ORDER BY created_at LIMIT 1"
            )
            
            # Проверяем наличие следующего
            has_next = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM contracts_physical WHERE id > $1 AND status = 'pending' AND is_hidden = FALSE)",
                contract['id']
            )
            
            await display_contract(callback, contract, "physical", has_next, False, total_count)
            
    except Exception as e:
        logger.error(f"Не удалось просмотреть договор физ. лица: {e}", exc_info=True)
        await callback.message.answer("Произошла ошибка при просмотре договора.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "view_legal")
async def view_legal_contracts_handler(callback: types.CallbackQuery):
    logger.info(f"Модератор {callback.from_user.id} просматривает договоры юр. лиц")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Получаем общее количество
            total_count = await conn.fetchval(
                "SELECT COUNT(*) FROM contracts_legal WHERE status = 'pending' AND is_hidden = FALSE"
            )
            
            if total_count == 0:
                await callback.message.edit_text(
                    "Нет договоров юр. лиц для обработки.",
                    reply_markup=None
                )
                await callback.message.answer(
                    "Модераторское меню:",
                    reply_markup=await get_moderator_menu()
                )
                return
            
            # Получаем первый договор
            contract = await conn.fetchrow(
                "SELECT * FROM contracts_legal WHERE status = 'pending' AND is_hidden = FALSE ORDER BY created_at LIMIT 1"
            )
            
            # Проверяем наличие следующего
            has_next = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM contracts_legal WHERE id > $1 AND status = 'pending' AND is_hidden = FALSE)",
                contract['id']
            )
            
            await display_contract(callback, contract, "legal", has_next, False, total_count)
            
    except Exception as e:
        logger.error(f"Не удалось просмотреть договор юр. лица: {e}", exc_info=True)
        await callback.message.answer("Произошла ошибка при просмотре договора.")
    finally:
        await callback.answer()

# ==================== ФУНКЦИЯ ОТОБРАЖЕНИЯ ДОГОВОРА ====================

async def display_contract(callback: types.CallbackQuery, contract: dict, contract_type: str, has_next: bool = False, has_prev: bool = False, total_count: int = 1):
    """Отображает договор с кнопками управления (использует HTML для форматирования)"""
    try:
        if contract_type == "physical":
            try:
                phone = decrypt_data(contract['phone'])
                passport_id = decrypt_data(contract['passport_id'])
            except Exception as e:
                logger.error(f"Не удалось расшифровать данные договора: {e}")
                phone = "[ошибка расшифровки]"
                passport_id = "[ошибка расшифровки]"
            
            # Используем HTML-форматирование
            text = (
                f"📄 <b>Договор физ. лица</b> (ID: {contract['id']})\n\n"
                f"👤 <b>Пользователь:</b> {html.escape(contract['username'] or str(contract['user_id']))}\n"
                f"🆔 <b>ID пользователя:</b> {html.escape(str(contract['user_id']))}\n"
                f"📅 <b>Дата создания:</b> {contract['created_at'].strftime('%d.%m.%Y %H:%M')}\n\n"
                f"📝 <b>Данные:</b>\n"
                f"└ ФИО: {html.escape(contract['full_name'])}\n"
                f"└ Номер паспорта: {html.escape(passport_id)}\n"
                f"└ Дата выдачи: {html.escape(contract['passport_issue_date'])}\n"
                f"└ Кем выдан: {html.escape(contract['passport_issued_by'])}\n"
                f"└ Адрес проживания: {html.escape(contract['living_address'])}\n"
                f"└ Адрес регистрации: {html.escape(contract['registration_address'] or '')}\n"
                f"└ Телефон: {html.escape(phone)}\n"
                f"└ Email: {html.escape(contract['email'])}\n"
                f"└ Синхр. с сайтом: {html.escape(contract.get('site_sync_status', 'неизвестно'))}"
            )
        else:
            try:
                phone = decrypt_data(contract['phone'])
                okpo = decrypt_data(contract['okpo']) if contract['okpo'] else "не указано"
                unp = decrypt_data(contract['unp'])
                account = decrypt_data(contract['account_number'])
            except Exception as e:
                logger.error(f"Не удалось расшифровать данные договора: {e}")
                phone = "[ошибка расшифровки]"
                okpo = "[ошибка расшифровки]"
                unp = "[ошибка расшифровки]"
                account = "[ошибка расшифровки]"
            
            text = (
                f"📄 <b>Договор юр. лица</b> (ID: {contract['id']})\n\n"
                f"👤 <b>Пользователь:</b> {html.escape(contract['username'] or str(contract['user_id']))}\n"
                f"🆔 <b>ID пользователя:</b> {html.escape(str(contract['user_id']))}\n"
                f"📅 <b>Дата создания:</b> {contract['created_at'].strftime('%d.%m.%Y %H:%M')}\n\n"
                f"📝 <b>Данные:</b>\n"
                f"└ Организация: {html.escape(contract['organization_name'])}\n"
                f"└ Почтовый адрес: {html.escape(contract['postal_address'])}\n"
                f"└ Юридический адрес: {html.escape(contract['legal_address'] or '')}\n"
                f"└ Телефон: {html.escape(phone)}\n"
                f"└ Вид деятельности: {html.escape(contract['activity_type'])}\n"
                f"└ ОКПО: {html.escape(okpo)}\n"
                f"└ УНП: {html.escape(unp)}\n"
                f"└ Расчетный счет: {html.escape(account)}\n"
                f"└ Банк: {html.escape(contract['bank_name'])}\n"
                f"└ БИК: {html.escape(contract['bank_bic'])}\n"
                f"└ Адрес банка: {html.escape(contract['bank_address'])}\n"
                f"└ Подписант: {html.escape(contract['signatory_name'])}\n"
                f"└ Основание полномочий: {html.escape(contract['authority_basis'])}\n"
                f"└ Должность: {html.escape(contract['position'])}\n"
                f"└ Email: {html.escape(contract['email'])}\n"
                f"└ Синхр. с сайтом: {html.escape(contract.get('site_sync_status', 'неизвестно'))}"
            )
        
        # Получаем актуальную информацию о наличии предыдущего/следующего договора
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            if contract_type == "physical":
                has_next = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM contracts_physical WHERE id > $1 AND status = 'pending' AND is_hidden = FALSE)",
                    contract['id']
                )
                has_prev = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM contracts_physical WHERE id < $1 AND status = 'pending' AND is_hidden = FALSE)",
                    contract['id']
                )
                total_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM contracts_physical WHERE status = 'pending' AND is_hidden = FALSE"
                )
            else:
                has_next = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM contracts_legal WHERE id > $1 AND status = 'pending' AND is_hidden = FALSE)",
                    contract['id']
                )
                has_prev = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM contracts_legal WHERE id < $1 AND status = 'pending' AND is_hidden = FALSE)",
                    contract['id']
                )
                total_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM contracts_legal WHERE status = 'pending' AND is_hidden = FALSE"
                )
        
        await callback.message.edit_text(
            text,
            parse_mode="HTML",
            reply_markup=await get_contract_action_menu(contract['id'], contract_type, has_next, has_prev, total_count)
        )
        
    except Exception as e:
        logger.error(f"Не удалось отобразить договор: {e}", exc_info=True)
        await callback.message.answer("Произошла ошибка при отображении договора.")

# ==================== ОБРАБОТЧИКИ ДЛЯ УДАЛЕНИЯ ИЗ СПИСКА ====================

@dp.callback_query(F.data.startswith("hide_contract:"))
async def hide_contract_handler(callback: types.CallbackQuery):
    """Скрывает договор из текущего списка (без подтверждения)"""
    parts = callback.data.split(":")
    if len(parts) != 3:
        await callback.answer("❌ Неверные данные", show_alert=True)
        return
    
    contract_type = parts[1]  # physical или legal
    contract_id = int(parts[2])
    moderator_id = callback.from_user.id
    
    # Скрываем договор
    success = await hide_contract_from_list(contract_id, contract_type, moderator_id)
    
    if success:
        await callback.answer("✅ Договор удалён из списка", show_alert=False)
        
        # Показываем следующий договор или возвращаемся в меню
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            # Проверяем, остались ли ещё договоры
            table = "contracts_physical" if contract_type == "physical" else "contracts_legal"
            remaining = await conn.fetchval(f"SELECT COUNT(*) FROM {table} WHERE status = 'pending' AND is_hidden = FALSE")
            
            if remaining > 0:
                # Показываем следующий договор
                if contract_type == "physical":
                    await view_physical_contracts_handler(callback)
                else:
                    await view_legal_contracts_handler(callback)
            else:
                # Возвращаемся в меню выбора типа договоров
                await callback.message.edit_text(
                    "✅ Все договоры обработаны.",
                    reply_markup=None
                )
                await callback.message.answer(
                    "Модераторское меню:",
                    reply_markup=await get_moderator_menu()
                )
    else:
        await callback.answer("❌ Ошибка при удалении из списка", show_alert=True)

@dp.callback_query(F.data.startswith("hide_all_"))
async def hide_all_contracts_handler(callback: types.CallbackQuery):
    """Скрывает все договоры из списка (без подтверждения)"""
    contract_type = callback.data.replace("hide_all_", "")  # physical или legal
    moderator_id = callback.from_user.id
    
    # Скрываем все договоры
    hidden_count = await hide_all_contracts_from_list(contract_type, moderator_id)
    
    if hidden_count > 0:
        await callback.answer(f"✅ Удалено {hidden_count} договоров из списка", show_alert=False)
        
        # Возвращаемся в меню выбора типа договоров
        await callback.message.edit_text(
            f"✅ Удалено {hidden_count} договоров из списка.",
            reply_markup=None
        )
        await callback.message.answer(
            "Модераторское меню:",
            reply_markup=await get_moderator_menu()
        )
    else:
        await callback.answer("❌ Нет договоров для удаления", show_alert=True)

# ==================== ОБРАБОТЧИКИ НАВИГАЦИИ ====================

@dp.callback_query(F.data.startswith("prev_contract:"))
async def prev_contract_handler(callback: types.CallbackQuery):
    """Показать предыдущий договор"""
    parts = callback.data.split(":")
    if len(parts) != 3:
        await callback.answer("❌ Неверные данные", show_alert=True)
        return
    
    contract_type = parts[1]
    current_id = int(parts[2])
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            if contract_type == "physical":
                contract = await conn.fetchrow(
                    "SELECT * FROM contracts_physical WHERE id < $1 AND status = 'pending' AND is_hidden = FALSE ORDER BY id DESC LIMIT 1",
                    current_id
                )
            else:
                contract = await conn.fetchrow(
                    "SELECT * FROM contracts_legal WHERE id < $1 AND status = 'pending' AND is_hidden = FALSE ORDER BY id DESC LIMIT 1",
                    current_id
                )
            
            if contract:
                await display_contract(callback, contract, contract_type)
            else:
                await callback.answer("Это первый договор в списке", show_alert=True)
    except Exception as e:
        logger.error(f"Ошибка при навигации: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при загрузке договора", show_alert=True)

@dp.callback_query(F.data.startswith("next_contract:"))
async def next_contract_handler(callback: types.CallbackQuery):
    """Показать следующий договор"""
    parts = callback.data.split(":")
    if len(parts) != 3:
        await callback.answer("❌ Неверные данные", show_alert=True)
        return
    
    contract_type = parts[1]
    current_id = int(parts[2])
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            if contract_type == "physical":
                contract = await conn.fetchrow(
                    "SELECT * FROM contracts_physical WHERE id > $1 AND status = 'pending' AND is_hidden = FALSE ORDER BY id LIMIT 1",
                    current_id
                )
            else:
                contract = await conn.fetchrow(
                    "SELECT * FROM contracts_legal WHERE id > $1 AND status = 'pending' AND is_hidden = FALSE ORDER BY id LIMIT 1",
                    current_id
                )
            
            if contract:
                await display_contract(callback, contract, contract_type)
            else:
                await callback.answer("Это последний договор в списке", show_alert=True)
    except Exception as e:
        logger.error(f"Ошибка при навигации: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при загрузке договора", show_alert=True)

@dp.callback_query(F.data == "moderator_back")
async def moderator_back_handler(callback: types.CallbackQuery):
    """Возврат в модераторское меню"""
    logger.info(f"Модератор {callback.from_user.id} вернулся в модераторское меню")
    await callback.message.edit_text(
        "Возвращаемся в модераторское меню",
        reply_markup=None
    )
    await callback.message.answer(
        "Модераторское меню:",
        reply_markup=await get_moderator_menu()
    )
    await callback.answer()

# ==================== ОТПРАВКА НА САЙТ ====================

async def set_news_active_state(news_id: int, active: bool, user_id: int) -> tuple[bool, dict]:
    """Отправляет запрос на сайт для изменения активности новости."""
    url = config.SITE_NEWS_URL
    if not url:
        logger.error("SITE_NEWS_URL не настроен")
        return False, {"error": "URL сервера не настроен"}

    payload = {
        "token": config.SITE_SECRET_TOKEN,
        "type": "deactivate_news" if not active else "activate_news",
        "news_id": news_id,
        "user_id": user_id
    }

    logger.info(f"📤 Отправка запроса на изменение активности новости {news_id} (active={active})")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=10) as resp:
                if resp.status != 200:
                    logger.error(f"HTTP ошибка {resp.status} от сайта")
                    return False, {"error": f"HTTP ошибка {resp.status}"}
                data = await resp.json()
                if data.get('success'):
                    logger.info(f"✅ Статус новости {news_id} успешно изменён на active={active}")
                    return True, data
                else:
                    error_msg = data.get('error', 'Неизвестная ошибка')
                    logger.error(f"Сайт вернул ошибку: {error_msg}")
                    return False, data
    except asyncio.TimeoutError:
        logger.error("Таймаут при запросе к сайту")
        return False, {"error": "Таймаут соединения с сервером"}
    except aiohttp.ClientError as e:
        logger.error(f"Сетевая ошибка: {e}")
        return False, {"error": "Ошибка соединения с сервером"}
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {e}", exc_info=True)
        return False, {"error": "Внутренняя ошибка бота"}

async def send_news_to_site(title: str, text: str, user_id: int, username: str = None) -> tuple[bool, dict, int | None, int | None]:
    """Отправляет новость на сайт через API. Возвращает (успех, ответ сайта, record_id, group_message_id)."""
    url = config.SITE_NEWS_URL
    if not url:
        logger.error("SITE_NEWS_URL не настроен")
        return False, {"error": "URL сервера не настроен"}, None, None
    
    payload = {
        "token": config.SITE_SECRET_TOKEN,
        "type": "news",
        "title": title,
        "text": text,
        "user_id": user_id
    }
    
    pool = await get_db_connection()
    record_id = None
    async with pool.acquire() as conn:
        record_id = await conn.fetchval(
            "INSERT INTO news_publications (user_id, username, title, content, status) "
            "VALUES ($1, $2, $3, $4, $5) RETURNING id",
            user_id,
            username,
            title,
            text,
            'pending'
        )
    
    group_message_id = None
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=10) as resp:
                if resp.status != 200:
                    logger.error(f"HTTP ошибка {resp.status} от сайта")
                    error_text = f"HTTP ошибка {resp.status}"
                    async with pool.acquire() as conn:
                        await conn.execute(
                            "UPDATE news_publications SET status = $1, error_message = $2 WHERE id = $3",
                            'error', error_text, record_id
                        )
                    return False, {"error": error_text}, record_id, None
                
                data = await resp.json()
                if data.get('success'):
                    site_news_id = data['id']
                    async with pool.acquire() as conn:
                        await conn.execute(
                            "UPDATE news_publications SET status = $1, site_news_id = $2, published_at = CURRENT_TIMESTAMP WHERE id = $3",
                            'success', site_news_id, record_id
                        )
                    logger.info(f"✅ Новость успешно отправлена на сайт, ID: {site_news_id}")
                    
                    # --- ПУБЛИКАЦИЯ В TELEGRAM-ГРУППУ ---
                    if config.TELEGRAM_GROUP_ID and await is_button_enabled('button_publish_to_group'):
                        try:
                            group_text = (
                                f"‼️ <b>Уважаемые клиенты</b> ‼️\n\n"
                                f"🔉 <b>{html.escape(title)}</b>\n\n"
                                f"⛽️ {html.escape(text)}"
                            )
                            sent_msg = await bot.send_message(
                                config.TELEGRAM_GROUP_ID,
                                group_text,
                                parse_mode="HTML"
                            )
                            group_message_id = sent_msg.message_id
                            logger.info(f"📢 Новость опубликована в Telegram-группе {config.TELEGRAM_GROUP_ID}, message_id={group_message_id}")
                        except Exception as e:
                            logger.error(f"Не удалось отправить новость в Telegram-группу: {e}", exc_info=True)
                    # --- КОНЕЦ БЛОКА ---
                    
                    return True, data, record_id, group_message_id
                else:
                    error_msg = data.get('error', 'Неизвестная ошибка')
                    async with pool.acquire() as conn:
                        await conn.execute(
                            "UPDATE news_publications SET status = $1, error_message = $2 WHERE id = $3",
                            'error', error_msg, record_id
                        )
                    return False, data, record_id, None
    except asyncio.TimeoutError:
        logger.error("Таймаут при отправке новости на сайт")
        error_msg = "Таймаут соединения с сервером"
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE news_publications SET status = $1, error_message = $2 WHERE id = $3",
                'error', error_msg, record_id
            )
        return False, {"error": error_msg}, record_id, None
    except aiohttp.ClientError as e:
        logger.error(f"Сетевая ошибка: {e}")
        error_msg = "Ошибка соединения с сервером"
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE news_publications SET status = $1, error_message = $2 WHERE id = $3",
                'error', error_msg, record_id
            )
        return False, {"error": error_msg}, record_id, None
    except Exception as e:
        logger.error(f"Неожиданная ошибка в send_news_to_site: {e}", exc_info=True)
        error_msg = "Внутренняя ошибка бота"
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE news_publications SET status = $1, error_message = $2 WHERE id = $3",
                'error', error_msg, record_id
            )
        return False, {"error": error_msg}, record_id, None

async def send_contract_to_site(contract_data: dict, contract_type: str, user_id: int, username: str = None) -> tuple[bool, dict, int | None]:
    """Отправляет данные договора на сайт через API."""
    url = config.SITE_NEWS_URL
    if not url:
        logger.error("SITE_NEWS_URL не настроен")
        return False, {"error": "URL сервера не настроен"}, None

    site_type = "contract_physical" if contract_type == "physical" else "contract_legal"

    if contract_type == "physical":
        detail_text = (
            f"👤 ФИО: {contract_data['full_name']}\n"
            f"🆔 Номер паспорта: {contract_data['passport_id']}\n"
            f"📅 Дата выдачи: {contract_data['passport_issue_date']}\n"
            f"🏢 Кем выдан: {contract_data['passport_issued_by']}\n"
            f"🏠 Адрес проживания: {contract_data['living_address']}\n"
            f"📋 Адрес регистрации: {contract_data['registration_address']}\n"
            f"📞 Телефон: {contract_data['phone']}\n"
            f"✉️ Email: {contract_data['email']}"
        )
        main_name = contract_data['full_name']
    else:
        detail_text = (
            f"🏢 Организация: {contract_data['organization_name']}\n"
            f"📮 Почтовый адрес: {contract_data['postal_address']}\n"
            f"⚖️ Юридический адрес: {contract_data['legal_address']}\n"
            f"📞 Телефон: {contract_data['phone']}\n"
            f"📋 Вид деятельности: {contract_data['activity_type']}\n"
            f"🔢 ОКПО: {contract_data.get('okpo', 'не указано')}\n"
            f"🔢 УНП: {contract_data['unp']}\n"
            f"💰 Расчётный счёт: {contract_data['account_number']}\n"
            f"🏦 Банк: {contract_data['bank_name']}\n"
            f"🔢 БИК: {contract_data['bank_bic']}\n"
            f"🏠 Адрес банка: {contract_data['bank_address']}\n"
            f"✍️ Подписант: {contract_data['signatory_name']}\n"
            f"📋 Основание полномочий: {contract_data['authority_basis']}\n"
            f"👔 Должность: {contract_data['position']}\n"
            f"✉️ Email: {contract_data['email']}"
        )
        main_name = contract_data['organization_name']

    user_info = f"Telegram ID: {user_id}"
    if username:
        user_info += f", Username: @{username}"
    detail_text += f"\n\n{user_info}"

    payload = {
        "token": config.SITE_SECRET_TOKEN,
        "type": site_type,
        "name": main_name,
        "detail_text": detail_text,
        "user_id": user_id,
        "contract_data": contract_data,
        "submission_date": datetime.now().isoformat()
    }

    logger.info(f"📤 Отправка договора типа {site_type} на сайт для пользователя {user_id}")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=10) as resp:
                if resp.status != 200:
                    logger.error(f"HTTP ошибка {resp.status} от сайта")
                    return False, {"error": f"HTTP ошибка {resp.status}"}, None

                data = await resp.json()
                if data.get('success'):
                    logger.info(f"✅ Договор успешно отправлен на сайт, ID записи: {data.get('id')}")
                    return True, data, data.get('id')
                else:
                    error_msg = data.get('error', 'Неизвестная ошибка')
                    logger.error(f"Сайт вернул ошибку: {error_msg}")
                    return False, data, None

    except asyncio.TimeoutError:
        logger.error("Таймаут при отправке договора на сайт")
        return False, {"error": "Таймаут соединения с сервером"}, None
    except aiohttp.ClientError as e:
        logger.error(f"Сетевая ошибка: {e}")
        return False, {"error": "Ошибка соединения с сервером"}, None
    except Exception as e:
        logger.error(f"Неожиданная ошибка в send_contract_to_site: {e}", exc_info=True)
        return False, {"error": "Внутренняя ошибка бота"}, None

# ==================== MIDDLEWARE ====================

@dp.update.outer_middleware()
async def log_all_updates(handler, event: types.Update, data: dict):
    """Логирует все входящие обновления и обновляет last_activity"""
    start_time = datetime.now()
    
    if event.message:
        user = event.message.from_user
        text = event.message.text or '[не текст]'
        requests_logger.info(
            f"📨 СООБЩЕНИЕ | User: {user.id} (@{user.username}) | "
            f"Chat: {event.message.chat.id} | Text: {text[:100]}"
        )
        # Обновляем активность пользователя (fire-and-forget)
        asyncio.create_task(update_user_activity(user.id))
    elif event.callback_query:
        cb = event.callback_query
        user = cb.from_user
        requests_logger.info(
            f"🖱️ CALLBACK | User: {user.id} (@{user.username}) | "
            f"Data: {cb.data} | Message: {cb.message.message_id}"
        )
        asyncio.create_task(update_user_activity(user.id))
    
    try:
        result = await handler(event, data)
        
        duration = (datetime.now() - start_time).total_seconds()
        if duration > 1:
            logger.warning(f"⚠️ Медленный запрос ({duration:.2f}с): {event.update_id}")
        else:
            logger.debug(f"✅ Запрос обработан за {duration:.3f}с")
        
        return result
        
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(
            f"💥 Ошибка при обработке запроса {event.update_id}:\n"
            f"Ошибка: {e}\n"
            f"Время: {duration:.2f}с\n"
            f"Трассировка:\n{traceback.format_exc()}"
        )
        raise

# ==================== ОБРАБОТЧИКИ КОМАНД ====================

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    logger.info(f"Пользователь {message.from_user.id} запустил бота")
    try:
        await register_user(message.from_user)
        await message.answer(
            "Команда METAN.BY приветствует Вас!",
            reply_markup=await get_main_menu(message.from_user.id)
        )
    except Exception as e:
        logger.error(f"Ошибка в команде start: {e}", exc_info=True)
        await message.answer("Произошла ошибка. Пожалуйста, попробуйте позже.")

@dp.message(Command("help"))
async def cmd_help(message: types.Message):
    help_text = (
        "📌 Доступные функции:\n"
        f"{EMOJI_QUESTION} Консультация со специалистом\n"
        f"{EMOJI_MONEY} Расчёт окупаемости\n"
        f"{EMOJI_VIDEO}{EMOJI_BOOK}Полезная информация\n"
        f"{EMOJI_CONTRACT} Заключение договора"
    )
    await message.answer(help_text)

# ==================== ОБРАБОТЧИКИ ГЛАВНОГО МЕНЮ ====================

@dp.message(F.text == f"{EMOJI_QUESTION} Консультация со специалистом")
async def consultation_handler(message: types.Message, state: FSMContext):
    logger.info(f"Пользователь {message.from_user.id} запросил консультацию")
    cancel_kb = ReplyKeyboardBuilder()
    cancel_kb.button(text="❌ Отменить вопрос")
    cancel_kb.adjust(1)
    
    await message.answer(
        "Пожалуйста, напишите ваш вопрос. Мы постараемся ответить как можно скорее.",
        reply_markup=cancel_kb.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.waiting_for_question)

@dp.message(Form.waiting_for_question, F.text == "❌ Отменить вопрос")
async def cancel_question_handler(message: types.Message, state: FSMContext):
    logger.info(f"Пользователь {message.from_user.id} отменил вопрос")
    await message.answer(
        "Вопрос отменен.",
        reply_markup=await get_main_menu(message.from_user.id)
    )
    await state.clear()

@dp.message(Form.waiting_for_question)
async def process_question(message: types.Message, state: FSMContext):
    question = sanitize_input(message.text)
    user = message.from_user
    
    logger.info(f"Обработка вопроса от пользователя {user.id}")
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO questions (user_id, username, question) VALUES ($1, $2, $3)",
                user.id, user.username, question
            )
    except Exception as e:
        logger.error(f"Не удалось сохранить вопрос: {e}", exc_info=True)
        await message.answer("Произошла ошибка. Пожалуйста, попробуйте позже.")
        return
    
    user_mention = await get_user_mention_plain(user)
    admin_text = f"{EMOJI_NEW} Новый вопрос от {user_mention}\n\n{question}"
    moderator_text = f"{EMOJI_NEW} Новый вопрос (ID: {user.id})\n\n{question}"
    
    await notify_admins(admin_text, EMOJI_QUESTION, notification_type="question")
    await notify_moderators(moderator_text, EMOJI_QUESTION, notification_type="question")
    
    await message.answer(
        "Ваш вопрос получен и передан специалисту. Мы ответим вам как можно скорее.",
        reply_markup=await get_main_menu(user.id)
    )
    await state.clear()

# ==================== ОБРАБОТЧИКИ НОВОСТЕЙ ====================

@dp.message(F.text == "📰 Добавить новость на сайт")
async def add_news_start(message: types.Message, state: FSMContext):
    logger.info(f"Пользователь {message.from_user.id} начал добавление новости")
    if not await is_agnks(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    if not await is_button_enabled('button_add_news'):
        await message.answer("Функция добавления новостей временно отключена.")
        return
    
    await message.answer(
        "Введите заголовок новости:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(AddNewsStates.waiting_for_title)

@dp.message(AddNewsStates.waiting_for_title, F.text == "❌ Отменить заполнение")
async def cancel_add_news_title(message: types.Message, state: FSMContext):
    logger.info(f"Пользователь {message.from_user.id} отменил добавление новости")
    await state.clear()
    await message.answer(
        "Добавление новости отменено.",
        reply_markup=await get_main_menu(message.from_user.id)
    )

@dp.message(AddNewsStates.waiting_for_title)
async def add_news_title(message: types.Message, state: FSMContext):
    title = sanitize_input(message.text)
    if not title:
        await message.answer("Заголовок не может быть пустым. Попробуйте снова:")
        return
    
    await state.update_data(title=title)
    await message.answer(
        "Введите текст новости:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(AddNewsStates.waiting_for_text)

@dp.message(AddNewsStates.waiting_for_text, F.text == "❌ Отменить заполнение")
async def cancel_add_news_text(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Добавление новости отменено.",
        reply_markup=await get_main_menu(message.from_user.id)
    )

@dp.message(AddNewsStates.waiting_for_text)
async def add_news_text(message: types.Message, state: FSMContext):
    text = sanitize_input(message.text)
    if not text:
        await message.answer("Текст новости не может быть пустым. Попробуйте снова:")
        return
    
    data = await state.get_data()
    title = data['title']
    user_id = message.from_user.id
    username = message.from_user.username
    author_is_admin = await is_admin(user_id)
    author_is_agnks = await is_agnks(user_id) and not author_is_admin  # если AGNKS и не админ
    
    await message.answer("⏳ Отправляю новость на сайт...")
    
    success, result, record_id, group_message_id = await send_news_to_site(title, text, user_id, username)
    
    if success:
        site_news_id = result['id']
        user_mention = await get_user_mention_plain(message.from_user)
        
        news_text_preview = text[:500] + ('...' if len(text) > 500 else '')
        
        # Формируем текст уведомления
        notify_text_lines = [
            f"{EMOJI_NEW} Новая новость опубликована на сайте",
            f"👤 Автор: {user_mention}",
            f"📰 Заголовок: {title}",
            f"📄 Текст:\n{news_text_preview}",
            f"🆔 ID новости на сайте: {site_news_id}",
            f"📅 Дата: {datetime.now().strftime('%d.%m.%Y %H:%M')}"
        ]
        
        # Добавляем информацию о публикации в группу
        if config.TELEGRAM_GROUP_ID and await is_button_enabled('button_publish_to_group'):
            if group_message_id is not None:
                notify_text_lines.append("✅ Сообщение опубликовано в Telegram-группе")
            else:
                notify_text_lines.append("❌ Ошибка публикации в Telegram-группе (проверьте логи)")
        # Если настройка выключена, ничего не добавляем
        
        notify_text = "\n".join(notify_text_lines)
        
        # Строим кнопки
        builder = InlineKeyboardBuilder()
        builder.button(text="🔽 Деактивировать", callback_data=f"deactivate_news:{site_news_id}")
        
        if group_message_id is not None:
            builder.button(text="🗑️ Удалить из группы", callback_data=f"delete_group_message:{config.TELEGRAM_GROUP_ID}:{group_message_id}:{site_news_id}")
        
        # Расстановка кнопок
        if group_message_id is not None:
            builder.adjust(2)
        else:
            builder.adjust(1)
        
        reply_markup = builder.as_markup()
        
        # Уведомления админам
        if await is_notification_enabled('notify_admin_news'):
            try:
                await notify_admins(notify_text, EMOJI_NEW, notification_type="news", reply_markup=reply_markup)
            except Exception as e:
                logger.error(f"Не удалось отправить уведомление админам: {e}")
        
        # Уведомления модераторам (исключая автора)
        await notify_moderators(
            notify_text, EMOJI_NEW, notification_type="news",
            reply_markup=reply_markup if not author_is_admin else None,
            author_is_admin=author_is_admin,
            exclude_user_id=user_id
        )
        
        # Отправляем автору, если он не администратор
        if not author_is_admin:
            try:
                await bot.send_message(user_id, notify_text, reply_markup=reply_markup)
            except Exception as e:
                logger.error(f"Не удалось отправить уведомление автору {user_id}: {e}")
        
        # Уведомления AGNKS (исключая автора)
        await notify_agnks(notify_text, EMOJI_NEW, notification_type="news", author_is_agnks=author_is_agnks, exclude_user_id=user_id)
        
        await message.answer(
            f"✅ Новость успешно добавлена!\nID новости на сайте: {site_news_id}",
            reply_markup=await get_main_menu(user_id)
        )
    else:
        error_msg = result.get('error', 'Неизвестная ошибка')
        await message.answer(
            f"❌ Ошибка при добавлении новости: {error_msg}",
            reply_markup=await get_main_menu(user_id)
        )
    
    await state.clear()

# ==================== CALLBACK ДЛЯ ДЕАКТИВАЦИИ/АКТИВАЦИИ НОВОСТЕЙ ====================

@dp.callback_query(F.data.startswith("deactivate_news:"))
async def deactivate_news_callback(callback: types.CallbackQuery):
    parts = callback.data.split(":")
    if len(parts) != 2:
        await callback.answer("Неверные данные", show_alert=True)
        return
    news_id = int(parts[1])
    user_id = callback.from_user.id

    if not (await is_admin(user_id) or await is_agnks(user_id) or await is_moderator(user_id)):
        await callback.answer("У вас нет прав для этого действия", show_alert=True)
        return

    await callback.answer("⏳ Отправка запроса...")
    success, result = await set_news_active_state(news_id, active=False, user_id=user_id)

    if success:
        current_markup = callback.message.reply_markup
        new_rows = []
        if current_markup and current_markup.inline_keyboard:
            for row in current_markup.inline_keyboard:
                new_row = []
                for button in row:
                    if button.callback_data and button.callback_data.startswith("deactivate_news:"):
                        new_row.append(InlineKeyboardButton(
                            text="🔼 Активировать",
                            callback_data=f"activate_news:{news_id}"
                        ))
                    else:
                        new_row.append(button)
                if new_row:
                    new_rows.append(new_row)
        else:
            new_rows = [[InlineKeyboardButton(text="🔼 Активировать", callback_data=f"activate_news:{news_id}")]]
        new_markup = InlineKeyboardMarkup(inline_keyboard=new_rows)
        await callback.message.edit_reply_markup(reply_markup=new_markup)
        await callback.answer("✅ Новость деактивирована", show_alert=False)
    else:
        error_msg = result.get('error', 'Неизвестная ошибка')
        await callback.answer(f"❌ Ошибка: {error_msg}", show_alert=True)

@dp.callback_query(F.data.startswith("activate_news:"))
async def activate_news_callback(callback: types.CallbackQuery):
    parts = callback.data.split(":")
    if len(parts) != 2:
        await callback.answer("Неверные данные", show_alert=True)
        return
    news_id = int(parts[1])
    user_id = callback.from_user.id

    if not (await is_admin(user_id) or await is_agnks(user_id) or await is_moderator(user_id)):
        await callback.answer("У вас нет прав для этого действия", show_alert=True)
        return

    await callback.answer("⏳ Отправка запроса...")
    success, result = await set_news_active_state(news_id, active=True, user_id=user_id)

    if success:
        current_markup = callback.message.reply_markup
        new_rows = []
        if current_markup and current_markup.inline_keyboard:
            for row in current_markup.inline_keyboard:
                new_row = []
                for button in row:
                    if button.callback_data and button.callback_data.startswith("activate_news:"):
                        new_row.append(InlineKeyboardButton(
                            text="🔽 Деактивировать",
                            callback_data=f"deactivate_news:{news_id}"
                        ))
                    else:
                        new_row.append(button)
                if new_row:
                    new_rows.append(new_row)
        else:
            new_rows = [[InlineKeyboardButton(text="🔽 Деактивировать", callback_data=f"deactivate_news:{news_id}")]]
        new_markup = InlineKeyboardMarkup(inline_keyboard=new_rows)
        await callback.message.edit_reply_markup(reply_markup=new_markup)
        await callback.answer("✅ Новость активирована", show_alert=False)
    else:
        error_msg = result.get('error', 'Неизвестная ошибка')
        await callback.answer(f"❌ Ошибка: {error_msg}", show_alert=True)
        
@dp.callback_query(F.data.startswith("delete_group_message:"))
async def delete_group_message_handler(callback: types.CallbackQuery):
    parts = callback.data.split(":")
    if len(parts) != 4:
        await callback.answer("Неверные данные", show_alert=True)
        return
    try:
        chat_id = int(parts[1])
        message_id = int(parts[2])
        site_news_id = int(parts[3])
    except ValueError:
        await callback.answer("Неверные данные", show_alert=True)
        return

    user_id = callback.from_user.id
    if not (await is_admin(user_id) or await is_moderator(user_id) or await is_agnks(user_id)):
        await callback.answer("У вас нет прав для этого действия", show_alert=True)
        return

    try:
        await bot.delete_message(chat_id, message_id)
        await callback.answer("✅ Сообщение удалено из группы", show_alert=False)

        current_markup = callback.message.reply_markup
        if current_markup and current_markup.inline_keyboard:
            new_rows = []
            for row in current_markup.inline_keyboard:
                new_row = []
                for button in row:
                    if button.callback_data and button.callback_data.startswith("delete_group_message:"):
                        continue
                    new_row.append(button)
                if new_row:
                    new_rows.append(new_row)
            if new_rows:
                new_markup = InlineKeyboardMarkup(inline_keyboard=new_rows)
                await callback.message.edit_reply_markup(reply_markup=new_markup)
            else:
                await callback.message.edit_reply_markup(reply_markup=None)
    except Exception as e:
        logger.error(f"Ошибка при удалении сообщения {message_id} из чата {chat_id}: {e}")
        await callback.answer(f"❌ Не удалось удалить сообщение: {str(e)[:50]}", show_alert=True)

# ==================== ОБРАБОТЧИКИ РАСЧЁТА ОКУПАЕМОСТИ ====================

@dp.message(F.text == f"{EMOJI_MONEY} Расчёт окупаемости")
async def roi_handler(message: types.Message, state: FSMContext):
    logger.info(f"Пользователь {message.from_user.id} запросил расчёт окупаемости")
    
    builder = ReplyKeyboardBuilder()
    builder.button(text="Бензин")
    builder.button(text="ДТ")
    builder.button(text="❌ Отменить расчет")
    builder.adjust(2, 1)
    
    await message.answer(
        "Выберите тип топлива базовой модели автомобиля:",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.roi_fuel_type)

# !!! Обработчик отмены должен быть ПЕРВЫМ в списке обработчиков ROI !!!
@dp.message(Form.roi_fuel_type, F.text == "❌ Отменить расчет")
@dp.message(Form.roi_vehicle_weight, F.text == "❌ Отменить расчет")
@dp.message(Form.roi_mileage, F.text == "❌ Отменить расчет")
@dp.message(Form.roi_fuel_consumption, F.text == "❌ Отменить расчет")
async def cancel_roi_calculation(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Расчет отменен.",
        reply_markup=await get_main_menu(message.from_user.id)
    )

@dp.message(Form.roi_fuel_type)
async def process_fuel_type(message: types.Message, state: FSMContext):
    fuel_type = message.text
    if fuel_type not in ["Бензин", "ДТ"]:
        await message.answer("Пожалуйста, выберите тип топлива из предложенных вариантов")
        return
    
    await state.update_data(fuel_type=fuel_type)
    
    if fuel_type == "Бензин":
        builder = ReplyKeyboardBuilder()
        builder.button(text="До 3,5 тонн")
        builder.button(text="Свыше 3,5 тонн")
        builder.button(text="❌ Отменить расчет")
        builder.adjust(2, 1)
        
        await message.answer(
            "Выберите массу автомобиля:",
            reply_markup=builder.as_markup(resize_keyboard=True)
        )
        await state.set_state(Form.roi_vehicle_weight)
    else:
        await message.answer(
            "Для ДТ расчет выполняется для комбинированного режима работы (50% ДТ + 50% КПГ)\n\n"
            "Введите расход топлива базового автомобиля (л/100км):",
            reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить расчет").as_markup(resize_keyboard=True)
        )
        await state.set_state(Form.roi_fuel_consumption)

@dp.message(Form.roi_vehicle_weight)
async def process_vehicle_weight(message: types.Message, state: FSMContext):
    weight = message.text
    if weight not in ["До 3,5 тонн", "Свыше 3,5 тонн"]:
        await message.answer("Пожалуйста, выберите массу автомобиля из предложенных вариантов")
        return
    
    await state.update_data(vehicle_weight=weight)
    
    await message.answer(
        "Введите расход топлива базового автомобиля (л/100км):",
        reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить расчет").as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.roi_fuel_consumption)

@dp.message(Form.roi_fuel_consumption)
async def process_fuel_consumption(message: types.Message, state: FSMContext):
    try:
        fuel_consumption = float(message.text.replace(",", "."))
        if fuel_consumption <= 0:
            raise ValueError("Расход должен быть положительным числом")
            
        await state.update_data(fuel_consumption=fuel_consumption)
        
        await message.answer(
            "Введите предполагаемый пробег автомобиля в год (км):",
            reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить расчет").as_markup(resize_keyboard=True)
        )
        await state.set_state(Form.roi_mileage)
    except ValueError:
        await message.answer("Пожалуйста, введите корректное число (например: 8.5)")

@dp.message(Form.roi_mileage)
async def process_mileage(message: types.Message, state: FSMContext):
    try:
        mileage = float(message.text.replace(",", "."))
        if mileage <= 0:
            raise ValueError("Пробег должен быть положительным числом")
            
        data = await state.get_data()
        fuel_type = data['fuel_type']
        fuel_consumption = data['fuel_consumption']
        
        fuel_price = await get_fuel_price(fuel_type)
        cng_price = await get_cng_price()
        
        if fuel_type == 'Бензин':
            installation_cost = await get_installation_cost(fuel_type, data.get('vehicle_weight'))
        else:
            installation_cost = await get_installation_cost(fuel_type)
        
        annual_fuel_cost = (mileage / 100) * fuel_consumption * fuel_price
        
        if fuel_type == 'Бензин':
            annual_cng_cost = (mileage / 100) * fuel_consumption * cng_price
            annual_savings = annual_fuel_cost - annual_cng_cost
        else:
            diesel_part = (mileage / 100) * (fuel_consumption * 0.5) * fuel_price
            cng_part = (mileage / 100) * (fuel_consumption * 0.5) * cng_price
            annual_combined_cost = diesel_part + cng_part
            annual_savings = annual_fuel_cost - annual_combined_cost
        
        if annual_savings > 0:
            payback_period = installation_cost / (annual_savings / 12)
        else:
            payback_period = float('inf')
        
        if fuel_type == 'Бензин':
            result_text = (
                f"📊 Результаты расчета окупаемости для {fuel_type}:\n\n"
                f"Цена {fuel_type}: {fuel_price:.2f} руб/л\n"
                f"Цена КПГ: {cng_price:.2f} руб/м³\n"
                f"Стоимость переоборудования: {installation_cost:.0f} бел. руб.\n"
                f"Расход топлива: {fuel_consumption:.1f} л/100км\n"
                f"Годовые затраты на {fuel_type}: {annual_fuel_cost:.2f} бел. руб.\n"
                f"Годовые затраты на КПГ: {annual_cng_cost:.2f} бел. руб.\n"
                f"Годовая экономия: {annual_savings:.2f} бел. руб.\n"
                f"Срок окупаемости: {payback_period:.1f} месяцев\n\n"
                "*Примечание: расчет является ориентировочным"
            )
        else:
            result_text = (
                f"📊 Результаты расчета окупаемости для {fuel_type} (комбинированный режим):\n\n"
                f"Цена {fuel_type}: {fuel_price:.2f} руб/л\n"
                f"Цена КПГ: {cng_price:.2f} руб/м³\n"
                f"Стоимость переоборудования: {installation_cost:.0f} бел. руб.\n"
                f"Расход топлива: {fuel_consumption:.1f} л/100км (50% ДТ + 50% КПГ)\n"
                f"Годовые затраты на {fuel_type}: {annual_fuel_cost:.2f} бел. руб.\n"
                f"Годовые затраты в комбинированном режиме: {annual_combined_cost:.2f} бел. руб.\n"
                f"  - Часть на ДТ: {diesel_part:.2f} бел. руб.\n"
                f"  - Часть на КПГ: {cng_part:.2f} бел. руб.\n"
                f"Годовая экономия: {annual_savings:.2f} бел. руб.\n"
                f"Срок окупаемости: {payback_period:.1f} месяцев\n\n"
                "*Примечание: расчет является ориентировочным"
            )
        
        await message.answer(
            result_text,
            reply_markup=await get_main_menu(message.from_user.id)
        )
        
        await state.clear()
        
    except ValueError:
        await message.answer("Пожалуйста, введите корректное число (например: 15000)")

# ==================== ОБРАБОТЧИКИ ПОЛЕЗНОЙ ИНФОРМАЦИИ ====================

@dp.message(F.text == f"{EMOJI_VIDEO}{EMOJI_BOOK}Полезная информация")
async def experience_handler(message: types.Message):
    logger.info(f"Пользователь {message.from_user.id} запросил полезную информацию")
    await message.answer(
        "Выберите тип материалов:",
        reply_markup=await get_experience_menu()
    )

@dp.callback_query(F.data == "experience_video")
async def experience_video_handler(callback: types.CallbackQuery):
    logger.info(f"Пользователь {callback.from_user.id} выбрал видеоматериалы")
    
    text_lines = [
        r"🎥\ *Видеоматериалы по эксплуатации:*",
        "",
        r"1\. [Заправка автомобиля сжатым газом](https://metan\.by/upload/CNGRefuling\.mp4)",
        ""
    ]
    new_text = "\n".join(text_lines)
    new_markup = await get_experience_menu()
    current_text = callback.message.text
    current_markup = callback.message.reply_markup
    
    try:
        if current_text != new_text or str(current_markup) != str(new_markup):
            await callback.message.edit_text(
                new_text,
                parse_mode="MarkdownV2",
                reply_markup=new_markup
            )
        else:
            await callback.answer("Уже отображаются видеоматериалы")
            return
            
    except TelegramBadRequest as e:
        if "message is not modified" in str(e):
            await callback.answer("Уже отображаются видеоматериалы")
        else:
            logger.error(f"Ошибка Telegram API: {e}")
            await callback.answer("Ошибка при обновлении", show_alert=True)
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {e}")
        await callback.answer("Произошла ошибка", show_alert=True)
    finally:
        await callback.answer()

@dp.callback_query(F.data == "experience_print")
async def experience_print_handler(callback: types.CallbackQuery):
    logger.info(f"Пользователь {callback.from_user.id} выбрал печатные материалы")
    
    text_lines = [
        "📚 <b>Печатные материалы по эксплуатации:</b>",
        "",
        "1. <a href='https://metan.by/upload/27577.pdf'>Выписка из ГОСТ 27577-2000</a>",
        "2. <a href='https://metan.by/upload/public.pdf'>Публичный договор приобретения КПГ</a>",
    ]
    new_text = "\n".join(text_lines)
    new_markup = await get_experience_menu()
    current_text = callback.message.text
    current_markup = callback.message.reply_markup
    
    try:
        if current_text != new_text or str(current_markup) != str(new_markup):
            await callback.message.edit_text(
                new_text,
                parse_mode="HTML",
                reply_markup=new_markup,
                disable_web_page_preview=True
            )
        else:
            await callback.answer("Уже отображаются печатные издания")
            return
            
    except TelegramBadRequest as e:
        if "message is not modified" in str(e):
            await callback.answer("Уже отображаются печатные издания")
        else:
            logger.error(f"Ошибка Telegram API: {e}")
            await callback.answer("Ошибка при обновлении", show_alert=True)
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {e}")
        await callback.answer("Произошла ошибка", show_alert=True)
    finally:
        await callback.answer()
        
@dp.callback_query(F.data == "main_menu")
async def back_to_main_menu_handler(callback: types.CallbackQuery):
    logger.info(f"Пользователь {callback.from_user.id} вернулся в главное меню")
    await callback.message.edit_text(
        "Возвращаемся в главное меню",
        reply_markup=None
    )
    await callback.message.answer(
        "Главное меню:",
        reply_markup=await get_main_menu(callback.from_user.id)
    )
    await callback.answer()

# ==================== ОБРАБОТЧИКИ ДОГОВОРОВ ====================

@dp.message(F.text == f"{EMOJI_CONTRACT} Заключение договора")
async def contract_handler(message: types.Message):
    logger.info(f"Пользователь {message.from_user.id} запросил договор")
    await message.answer(
        "Выберите тип договора:",
        reply_markup=await get_contract_type_menu()
    )

@dp.callback_query(F.data == "contract_physical")
async def contract_physical_handler(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"Пользователь {callback.from_user.id} выбрал договор физ. лица")
    await callback.message.edit_text(
        "Вы выбрали договор для физического лица. Давайте заполним данные.",
        reply_markup=None
    )
    await callback.message.answer(
        "Введите ваше ФИО (в именительном падеже):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_full_name)
    await callback.answer()

@dp.message(Form.physical_full_name)
async def process_physical_full_name(message: types.Message, state: FSMContext):
    logger.info(f"Обработка ФИО для пользователя {message.from_user.id}")
    await state.update_data(full_name=sanitize_input(message.text))
    await message.answer(
        "Введите идентификационный номер паспорта:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_passport_id)

@dp.message(Form.physical_passport_id)
async def process_physical_passport_id(message: types.Message, state: FSMContext):
    logger.info(f"Обработка номера паспорта")
    await state.update_data(passport_id=sanitize_input(message.text))
    await message.answer(
        "Введите дату выдачи паспорта (ДД.ММ.ГГГГ):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_passport_issue_date)

@dp.message(Form.physical_passport_issue_date)
async def process_physical_passport_issue_date(message: types.Message, state: FSMContext):
    logger.info(f"Обработка даты выдачи паспорта")
    try:
        date = validate_passport_date(message.text)
        await state.update_data(passport_issue_date=date)
        await message.answer(
            "Введите кем выдан паспорт:",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.physical_passport_issued_by)
    except ValueError as e:
        await message.answer(str(e))

@dp.message(Form.physical_passport_issued_by)
async def process_physical_passport_issued_by(message: types.Message, state: FSMContext):
    logger.info(f"Обработка кем выдан паспорт")
    await state.update_data(passport_issued_by=sanitize_input(message.text))
    await message.answer(
        "Введите индекс и адрес проживания:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_living_address)

@dp.message(Form.physical_living_address)
async def process_physical_living_address(message: types.Message, state: FSMContext):
    logger.info(f"Обработка адреса проживания")
    await state.update_data(living_address=sanitize_input(message.text))
    
    builder = ReplyKeyboardBuilder()
    builder.button(text="✅ Совпадает")
    builder.button(text="❌ Отменить заполнение")
    builder.adjust(2)
    
    await message.answer(
        "Введите адрес регистрации или нажмите '✅ Совпадает' если совпадает с адресом проживания",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.physical_registration_address)

@dp.message(Form.physical_registration_address)
async def process_physical_registration_address(message: types.Message, state: FSMContext):
    logger.info(f"Обработка адреса регистрации")
    
    if message.text == "✅ Совпадает":
        data = await state.get_data()
        await state.update_data(registration_address=data['living_address'])
    else:
        await state.update_data(registration_address=sanitize_input(message.text))
    
    await message.answer(
        "Введите ваш телефон (+375XXXXXXXXX):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_phone)

@dp.message(Form.physical_phone)
async def process_physical_phone(message: types.Message, state: FSMContext):
    logger.info(f"Обработка телефона")
    try:
        phone = validate_phone(message.text)
        await state.update_data(phone=phone)
        await message.answer(
            "Введите ваш email:",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.physical_email)
    except ValueError as e:
        await message.answer(str(e))

@dp.message(Form.physical_email)
async def process_physical_email(message: types.Message, state: FSMContext):
    logger.info(f"Обработка email")
    try:
        email = validate_email(message.text)
        await state.update_data(email=email)
        
        data = await state.get_data()
        try:
            validated_data = PhysicalPersonData(**data)
            text = (
                "Проверьте введенные данные:\n\n"
                f"ФИО: {validated_data.full_name}\n"
                f"Номер паспорта: {validated_data.passport_id}\n"
                f"Дата выдачи: {validated_data.passport_issue_date}\n"
                f"Кем выдан: {validated_data.passport_issued_by}\n"
                f"Адрес проживания: {validated_data.living_address}\n"
                f"Адрес регистрации: {validated_data.registration_address}\n"
                f"Телефон: {validated_data.phone}\n"
                f"Email: {validated_data.email}\n\n"
                "Все верно?"
            )
            
            await message.answer(
                text,
                reply_markup=await get_confirm_menu("physical")
            )
            await state.set_state(Form.physical_confirm)
        except ValidationError as e:
            await message.answer(f"Ошибка в данных: {str(e)}")
    except ValueError as e:
        await message.answer(str(e))

@dp.callback_query(F.data == "confirm_physical", Form.physical_confirm)
async def confirm_physical_contract(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"Пользователь {callback.from_user.id} подтвердил договор физ. лица")
    user = callback.from_user
    data = await state.get_data()
    
    try:
        validated_data = PhysicalPersonData(**data)
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            contract_id = await conn.fetchval(
                "INSERT INTO contracts_physical (user_id, username, full_name, passport_id, passport_issue_date, "
                "passport_issued_by, living_address, registration_address, phone, email, site_sync_status) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
                user.id,
                user.username,
                validated_data.full_name,
                encrypt_data(validated_data.passport_id),
                validated_data.passport_issue_date,
                validated_data.passport_issued_by,
                validated_data.living_address,
                validated_data.registration_address,
                encrypt_data(validated_data.phone),
                validated_data.email,
                'pending'
            )
            
            contract_dict = validated_data.dict()
            success, result, site_contract_id = await send_contract_to_site(
                contract_dict,
                "physical",
                user.id,
                user.username
            )
            
            if success and site_contract_id:
                await conn.execute(
                    "UPDATE contracts_physical SET site_sync_status = 'success', site_contract_id = $1 WHERE id = $2",
                    site_contract_id, contract_id
                )
                site_status = "✅ успешно"
            else:
                error_msg = result.get('error', 'неизвестная ошибка')
                await conn.execute(
                    "UPDATE contracts_physical SET site_sync_status = 'failed' WHERE id = $1",
                    contract_id
                )
                site_status = f"❌ ошибка: {error_msg}"
        
        await callback.message.edit_text(
            "Данные сохранены. Наш менеджер свяжется с вами для завершения оформления договора.",
            reply_markup=None
        )
        await callback.message.answer(
            "Главное меню:",
            reply_markup=await get_main_menu(user.id)
        )
        
        user_mention = await get_user_mention_plain(user)
        admin_text = (
            f"{EMOJI_NEW} Новый договор (физ. лицо) от {user_mention}\n\n"
            f"ФИО: {validated_data.full_name}\n"
            f"Телефон: {validated_data.phone}\n"
            f"Email: {validated_data.email}\n"
            f"Синхронизация с сайтом: {site_status}"
        )
        
        await notify_admins(admin_text, EMOJI_CONTRACT, notification_type="contract")
        
        await state.clear()
    except Exception as e:
        logger.error(f"Не удалось сохранить договор: {e}", exc_info=True)
        await callback.message.answer("Произошла ошибка при сохранении данных.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "contract_legal")
async def contract_legal_handler(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"Пользователь {callback.from_user.id} выбрал договор юр. лица")
    await callback.message.edit_text(
        "Вы выбрали договор для юридического лица. Давайте заполним данные.",
        reply_markup=None
    )
    await callback.message.answer(
        "Введите полное наименование организации:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_organization_name)
    await callback.answer()

@dp.message(Form.legal_organization_name)
async def process_legal_organization_name(message: types.Message, state: FSMContext):
    logger.info(f"Обработка названия организации")
    await state.update_data(organization_name=sanitize_input(message.text))
    await message.answer(
        "Введите индекс и почтовый адрес организации:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_postal_address)

@dp.message(Form.legal_postal_address)
async def process_legal_postal_address(message: types.Message, state: FSMContext):
    logger.info(f"Обработка почтового адреса")
    await state.update_data(postal_address=sanitize_input(message.text))
    
    builder = ReplyKeyboardBuilder()
    builder.button(text="✅ Совпадает")
    builder.button(text="❌ Отменить заполнение")
    builder.adjust(2)
    
    await message.answer(
        "Введите индекс и юридический адрес (если отличается от почтового) или нажмите '✅ Совпадает':",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.legal_legal_address)

@dp.message(Form.legal_legal_address)
async def process_legal_legal_address(message: types.Message, state: FSMContext):
    logger.info(f"Обработка юридического адреса")
    if message.text == "✅ Совпадает":
        data = await state.get_data()
        await state.update_data(legal_address=data['postal_address'])
    else:
        await state.update_data(legal_address=sanitize_input(message.text))
    
    await message.answer(
        "Введите контактный телефон (+375XXXXXXXXX):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_phone)

@dp.message(Form.legal_phone)
async def process_legal_phone(message: types.Message, state: FSMContext):
    logger.info(f"Обработка телефона")
    try:
        phone = validate_phone(message.text)
        await state.update_data(phone=phone)
        await message.answer(
            "Введите вид деятельности организации:",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_activity_type)
    except ValueError as e:
        await message.answer(str(e))

@dp.message(Form.legal_activity_type)
async def process_legal_activity_type(message: types.Message, state: FSMContext):
    logger.info(f"Обработка вида деятельности")
    await state.update_data(activity_type=sanitize_input(message.text))
    
    builder = ReplyKeyboardBuilder()
    builder.button(text="➡️ Пропустить")
    builder.button(text="❌ Отменить заполнение")
    builder.adjust(2)
    
    await message.answer(
        "Введите ОКПО организации (8 цифр) или нажмите 'Пропустить':",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.legal_okpo)

@dp.message(Form.legal_okpo)
async def process_legal_okpo(message: types.Message, state: FSMContext):
    if message.text == "➡️ Пропустить":
        await state.update_data(okpo=None)
        await message.answer(
            "Введите УНП организации (9 цифр):",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_unp)
        return
    
    try:
        okpo = validate_okpo(message.text) if message.text else None
        await state.update_data(okpo=okpo)
        await message.answer(
            "Введите УНП организации (9 цифр):",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_unp)
    except ValueError as e:
        await message.answer(str(e))
		
@dp.message(Form.legal_unp)
async def process_legal_unp(message: types.Message, state: FSMContext):
    logger.info(f"Обработка УНП")
    try:
        unp = validate_unp(message.text)
        await state.update_data(unp=unp)
        await message.answer(
            "Введите расчетный счет (IBAN BY...):",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_account_number)
    except ValueError as e:
        await message.answer(str(e))

@dp.message(Form.legal_account_number)
async def process_legal_account_number(message: types.Message, state: FSMContext):
    logger.info(f"Обработка номера счёта")
    try:
        account = validate_account(message.text)
        await state.update_data(account_number=account)
        await message.answer(
            "Введите название банка:",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_bank_name)
    except ValueError as e:
        await message.answer(str(e))

@dp.message(Form.legal_bank_name)
async def process_legal_bank_name(message: types.Message, state: FSMContext):
    logger.info(f"Обработка названия банка")
    await state.update_data(bank_name=sanitize_input(message.text))
    await message.answer(
        "Введите БИК банка:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_bank_bic)

@dp.message(Form.legal_bank_bic)
async def process_legal_bank_bic(message: types.Message, state: FSMContext):
    logger.info(f"Обработка БИК банка")
    await state.update_data(bank_bic=sanitize_input(message.text))
    await message.answer(
        "Введите адрес банка:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_bank_address)

@dp.message(Form.legal_bank_address)
async def process_legal_bank_address(message: types.Message, state: FSMContext):
    logger.info(f"Обработка адреса банка")
    await state.update_data(bank_address=sanitize_input(message.text))
    await message.answer(
        "Введите ФИО подписанта:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_signatory_name)

@dp.message(Form.legal_signatory_name)
async def process_legal_signatory_name(message: types.Message, state: FSMContext):
    logger.info(f"Обработка ФИО подписанта")
    await state.update_data(signatory_name=sanitize_input(message.text))
    await message.answer(
        "Введите основание полномочий подписанта (Устав, Доверенность и т.д.):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_authority_basis)

@dp.message(Form.legal_authority_basis)
async def process_legal_authority_basis(message: types.Message, state: FSMContext):
    logger.info(f"Обработка основания полномочий")
    await state.update_data(authority_basis=sanitize_input(message.text))
    await message.answer(
        "Введите должность подписанта:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_position)

@dp.message(Form.legal_position)
async def process_legal_position(message: types.Message, state: FSMContext):
    logger.info(f"Обработка должности подписанта")
    await state.update_data(position=sanitize_input(message.text))
    await message.answer(
        "Введите email для связи:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_email)

@dp.message(Form.legal_email)
async def process_legal_email(message: types.Message, state: FSMContext):
    logger.info(f"Обработка email")
    try:
        email = validate_email(message.text)
        await state.update_data(email=email)
        
        data = await state.get_data()
        try:
            validated_data = LegalPersonData(**data)
            text = (
                "Проверьте введенные данные:\n\n"
                f"Организация: {validated_data.organization_name}\n"
                f"Почтовый адрес: {validated_data.postal_address}\n"
                f"Юридический адрес: {validated_data.legal_address}\n"
                f"Телефон: {validated_data.phone}\n"
                f"Вид деятельности: {validated_data.activity_type}\n"
                f"ОКПО: {validated_data.okpo}\n"
                f"УНП: {validated_data.unp}\n"
                f"Расчетный счет: {validated_data.account_number}\n"
                f"Банк: {validated_data.bank_name}\n"
                f"БИК: {validated_data.bank_bic}\n"
                f"Адрес банка: {validated_data.bank_address}\n"
                f"Подписант: {validated_data.signatory_name}\n"
                f"Основание полномочий: {validated_data.authority_basis}\n"
                f"Должность: {validated_data.position}\n"
                f"Email: {validated_data.email}\n\n"
                "Все верно?"
            )
            
            await message.answer(
                text,
                reply_markup=await get_confirm_menu("legal")
            )
            await state.set_state(Form.legal_confirm)
        except ValidationError as e:
            await message.answer(f"Ошибка в данных: {str(e)}")
    except ValueError as e:
        await message.answer(str(e))

@dp.callback_query(F.data == "confirm_legal", Form.legal_confirm)
async def confirm_legal_contract(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"Пользователь {callback.from_user.id} подтвердил договор юр. лица")
    user = callback.from_user
    data = await state.get_data()
    
    try:
        validated_data = LegalPersonData(**data)
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            contract_id = await conn.fetchval(
                "INSERT INTO contracts_legal (user_id, username, organization_name, postal_address, legal_address, "
                "phone, activity_type, okpo, unp, account_number, bank_name, bank_bic, bank_address, "
                "signatory_name, authority_basis, position, email, site_sync_status) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id",
                user.id,
                user.username,
                validated_data.organization_name,
                validated_data.postal_address,
                validated_data.legal_address,
                encrypt_data(validated_data.phone),
                validated_data.activity_type,
                encrypt_data(validated_data.okpo) if validated_data.okpo is not None else None,
                encrypt_data(validated_data.unp),
                encrypt_data(validated_data.account_number),
                validated_data.bank_name,
                validated_data.bank_bic,
                validated_data.bank_address,
                validated_data.signatory_name,
                validated_data.authority_basis,
                validated_data.position,
                validated_data.email,
                'pending'
            )
            
            contract_dict = validated_data.dict()
            success, result, site_contract_id = await send_contract_to_site(
                contract_dict,
                "legal",
                user.id,
                user.username
            )
            
            if success and site_contract_id:
                await conn.execute(
                    "UPDATE contracts_legal SET site_sync_status = 'success', site_contract_id = $1 WHERE id = $2",
                    site_contract_id, contract_id
                )
                site_status = "✅ успешно"
            else:
                error_msg = result.get('error', 'неизвестная ошибка')
                await conn.execute(
                    "UPDATE contracts_legal SET site_sync_status = 'failed' WHERE id = $1",
                    contract_id
                )
                site_status = f"❌ ошибка: {error_msg}"
        
        await callback.message.edit_text(
            "Данные сохранены. Наш менеджер свяжется с вами для завершения оформления договора.",
            reply_markup=None
        )
        await callback.message.answer(
            "Главное меню:",
            reply_markup=await get_main_menu(user.id)
        )
        
        user_mention = await get_user_mention_plain(user)
        admin_text = (
            f"{EMOJI_NEW} Новый договор (юр. лицо) от {user_mention}\n\n"
            f"Организация: {validated_data.organization_name}\n"
            f"Телефон: {validated_data.phone}\n"
            f"Email: {validated_data.email}\n"
            f"Синхронизация с сайтом: {site_status}"
        )
        
        await notify_admins(admin_text, EMOJI_CONTRACT, notification_type="contract")
        
        await state.clear()
    except Exception as e:
        logger.error(f"Не удалось сохранить договор: {e}", exc_info=True)
        await callback.message.answer("Произошла ошибка при сохранении данных.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "cancel_confirm", Form.physical_confirm)
@dp.callback_query(F.data == "cancel_confirm", Form.legal_confirm)
async def cancel_confirm_handler(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"Пользователь {callback.from_user.id} отменил подтверждение")
    await callback.message.edit_text(
        "Заполнение отменено.",
        reply_markup=None
    )
    await callback.message.answer(
        "Главное меню:",
        reply_markup=await get_main_menu(callback.from_user.id)
    )
    await state.clear()
    await callback.answer()

# ==================== ОБРАБОТЧИКИ МОДЕРАТОРА ====================

@dp.message(F.text == "🔧 Модераторское меню")
async def moderator_menu_handler(message: types.Message):
    logger.info(f"Пользователь {message.from_user.id} вошёл в модераторское меню")
    if not await is_moderator(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    await message.answer(
        "Модераторское меню:",
        reply_markup=await get_moderator_menu()
    )

@dp.message(F.text == "📋 Неотвеченные вопросы")
async def unanswered_questions_handler(message: types.Message):
    if not await is_moderator(message.from_user.id):
        return
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            questions = await conn.fetch(
                "SELECT id, user_id, username, question FROM questions "
                "WHERE answer IS NULL AND skipped_at IS NULL "
                "ORDER BY created_at LIMIT 1"
            )
            
            if not questions:
                await message.answer("Нет неотвеченных вопросов.", reply_markup=await get_moderator_menu())
                return
                
            question = questions[0]
            
            has_next = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE id > $1 AND answer IS NULL AND skipped_at IS NULL)",
                question['id']
            )
            
            question_text = (
                f"Вопрос от пользователя {question['username'] or question['user_id']}:\n\n"
                f"{question['question']}"
            )
            
            await message.answer(
                question_text,
                reply_markup=await get_question_action_menu(question['id'], has_next, False)
            )
    except Exception as e:
        logger.error(f"Не удалось получить неотвеченные вопросы: {e}", exc_info=True)
        await message.answer("Произошла ошибка при получении вопросов.")

@dp.callback_query(F.data.startswith("answer_"))
async def answer_question_handler(callback: types.CallbackQuery, state: FSMContext):
    question_id = int(callback.data.split("_")[1])
    await state.update_data(question_id=question_id)
    
    await callback.message.edit_text(
        "Введите ответ на вопрос:",
        reply_markup=None
    )
    await callback.message.answer(
        "Отправьте текст ответа:",
        reply_markup=await get_cancel_reply_keyboard()
    )
    await state.set_state(Form.waiting_for_answer)
    await callback.answer()

@dp.message(Form.waiting_for_answer, F.text == "❌ Отменить ответ")
async def cancel_answer_handler(message: types.Message, state: FSMContext):
    logger.info(f"Модератор {message.from_user.id} отменил ответ")
    await message.answer(
        "Ответ отменен.",
        reply_markup=await get_moderator_menu()
    )
    await state.clear()

@dp.message(Form.waiting_for_answer)
async def process_answer(message: types.Message, state: FSMContext):
    answer = sanitize_input(message.text)
    data = await state.get_data()
    question_id = data['question_id']
    moderator = message.from_user
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            question = await conn.fetchrow(
                "SELECT user_id, question FROM questions WHERE id = $1",
                question_id
            )
            
            if not question:
                await message.answer("Вопрос не найден.", reply_markup=await get_moderator_menu())
                await state.clear()
                return
                
            await conn.execute(
                "UPDATE questions SET answer = $1, answered_by = $2, answered_at = CURRENT_TIMESTAMP WHERE id = $3",
                answer,
                moderator.username or moderator.full_name,
                question_id
            )
            
            try:
                await bot.send_message(
                    question['user_id'],
                    f"Ответ на ваш вопрос:\n\n{question['question']}\n\n{answer}"
                )
            except Exception as e:
                logger.warning(f"Не удалось уведомить пользователя: {e}")
                
            await message.answer(
                "Ответ сохранен и отправлен пользователю.",
                reply_markup=await get_moderator_menu()
            )
            
            moderator_mention = await get_user_mention_plain(moderator)
            notify_text = f"Вопрос ID {question_id} был отвечен модератором {moderator_mention}"
            await notify_admins(notify_text, EMOJI_DONE)
            
    except Exception as e:
        logger.error(f"Не удалось обработать ответ: {e}", exc_info=True)
        await message.answer("Произошла ошибка при сохранении ответа.")
    finally:
        await state.clear()

@dp.callback_query(F.data.startswith("skip_"))
async def skip_question_handler(callback: types.CallbackQuery):
    parts = callback.data.split("_")
    question_id = int(parts[1])
    moderator = callback.from_user
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE questions SET skipped_at = CURRENT_TIMESTAMP WHERE id = $1",
                question_id
            )
            
            await callback.message.edit_text(
                "Вопрос пропущен.",
                reply_markup=None
            )
            
            moderator_mention = await get_user_mention_plain(moderator)
            notify_text = f"Вопрос ID {question_id} был пропущен модератором {moderator_mention}"
            await notify_moderators(notify_text, EMOJI_WARNING)
            
    except Exception as e:
        logger.error(f"Не удалось пропустить вопрос: {e}", exc_info=True)
    finally:
        await callback.answer()
        
@dp.callback_query(F.data.startswith("prev_question_"))
async def prev_question_handler(callback: types.CallbackQuery):
    """Показать предыдущий вопрос"""
    question_id = int(callback.data.split("_")[2])
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            prev = await conn.fetchrow(
                "SELECT id, user_id, username, question FROM questions "
                "WHERE id < $1 AND answer IS NULL AND skipped_at IS NULL "
                "ORDER BY id DESC LIMIT 1",
                question_id
            )
            if not prev:
                await callback.answer("Это первый вопрос", show_alert=True)
                return
            has_next = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE id > $1 AND answer IS NULL AND skipped_at IS NULL)",
                prev['id']
            )
            has_prev = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE id < $1 AND answer IS NULL AND skipped_at IS NULL)",
                prev['id']
            )
            text = f"Вопрос от пользователя {prev['username'] or prev['user_id']}:\n\n{prev['question']}"
            await callback.message.edit_text(
                text,
                reply_markup=await get_question_action_menu(prev['id'], has_next, has_prev)
            )
            await callback.answer()
    except Exception as e:
        logger.error(f"Ошибка при загрузке предыдущего вопроса: {e}", exc_info=True)
        await callback.answer("Ошибка", show_alert=True)

@dp.callback_query(F.data.startswith("next_question_"))
async def next_question_handler(callback: types.CallbackQuery):
    """Показать следующий вопрос"""
    question_id = int(callback.data.split("_")[2])
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            next_q = await conn.fetchrow(
                "SELECT id, user_id, username, question FROM questions "
                "WHERE id > $1 AND answer IS NULL AND skipped_at IS NULL "
                "ORDER BY id LIMIT 1",
                question_id
            )
            if not next_q:
                await callback.answer("Это последний вопрос", show_alert=True)
                return
            has_next = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE id > $1 AND answer IS NULL AND skipped_at IS NULL)",
                next_q['id']
            )
            has_prev = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE id < $1 AND answer IS NULL AND skipped_at IS NULL)",
                next_q['id']
            )
            text = f"Вопрос от пользователя {next_q['username'] or next_q['user_id']}:\n\n{next_q['question']}"
            await callback.message.edit_text(
                text,
                reply_markup=await get_question_action_menu(next_q['id'], has_next, has_prev)
            )
            await callback.answer()
    except Exception as e:
        logger.error(f"Ошибка при загрузке следующего вопроса: {e}", exc_info=True)
        await callback.answer("Ошибка", show_alert=True)

@dp.callback_query(F.data == "cancel_question")
async def cancel_question_view_handler(callback: types.CallbackQuery):
    """Скрыть вопрос (вернуться в меню модератора)"""
    await callback.message.delete()
    await callback.message.answer(
        "Модераторское меню:",
        reply_markup=await get_moderator_menu()
    )
    await callback.answer()

# ==================== ОБРАБОТЧИКИ АДМИНИСТРАТОРА ====================

@dp.message(F.text == "👑 Админ-панель")
async def admin_menu_handler(message: types.Message):
    logger.info(f"Пользователь {message.from_user.id} вошёл в админ-панель")
    if not await is_admin(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    await message.answer(
        "Админ-панель:",
        reply_markup=await get_admin_menu()
    )

@dp.message(F.text == "📊 Статистика")
async def admin_stats_handler(message: types.Message):
    if not await is_admin(message.from_user.id):
        return
    
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            # Базовые подсчёты
            users_total = await conn.fetchval("SELECT COUNT(*) FROM users")
            users_week = await conn.fetchval("SELECT COUNT(*) FROM users WHERE last_activity > CURRENT_DATE - INTERVAL '7 days'")
            users_month = await conn.fetchval("SELECT COUNT(*) FROM users WHERE last_activity > CURRENT_DATE - INTERVAL '30 days'")
            
            questions_total = await conn.fetchval("SELECT COUNT(*) FROM questions")
            questions_answered = await conn.fetchval("SELECT COUNT(*) FROM questions WHERE answer IS NOT NULL")
            questions_pending = await conn.fetchval("SELECT COUNT(*) FROM questions WHERE answer IS NULL AND skipped_at IS NULL")
            
            # Среднее время ответа (в часах)
            avg_response_time = await conn.fetchval("""
                SELECT AVG(EXTRACT(EPOCH FROM (answered_at - created_at)) / 3600) 
                FROM questions WHERE answer IS NOT NULL
            """)
            avg_response_time = round(avg_response_time, 1) if avg_response_time else 0
            
            contracts_physical_total = await conn.fetchval("SELECT COUNT(*) FROM contracts_physical")
            contracts_physical_pending = await conn.fetchval("SELECT COUNT(*) FROM contracts_physical WHERE status = 'pending' AND is_hidden = FALSE")
            contracts_legal_total = await conn.fetchval("SELECT COUNT(*) FROM contracts_legal")
            contracts_legal_pending = await conn.fetchval("SELECT COUNT(*) FROM contracts_legal WHERE status = 'pending' AND is_hidden = FALSE")
            
            news_total = await conn.fetchval("SELECT COUNT(*) FROM news_publications")
            news_success = await conn.fetchval("SELECT COUNT(*) FROM news_publications WHERE status = 'success'")
            news_week = await conn.fetchval("SELECT COUNT(*) FROM news_publications WHERE created_at > CURRENT_DATE - INTERVAL '7 days'")
            
            # Количество модераторов и AGNKS
            moderators_count = len(await get_moderators())
            agnks_count = len(await get_agnks_users())
            
            text = (
                "📊 **Расширенная статистика бота**\n\n"
                "👥 **Пользователи:**\n"
                f"├ Всего: {users_total}\n"
                f"├ Активны за 7 дней: {users_week}\n"
                f"└ Активны за 30 дней: {users_month}\n\n"
                "❓ **Вопросы:**\n"
                f"├ Всего: {questions_total}\n"
                f"├ Отвечено: {questions_answered}\n"
                f"├ В ожидании: {questions_pending}\n"
                f"└ Среднее время ответа: {avg_response_time} ч.\n\n"
                "📝 **Договоры:**\n"
                f"├ Физ. лица: всего {contracts_physical_total} (на рассмотрении: {contracts_physical_pending})\n"
                f"└ Юр. лица: всего {contracts_legal_total} (на рассмотрении: {contracts_legal_pending})\n\n"
                "📰 **Новости:**\n"
                f"├ Всего публикаций: {news_total} (успешных: {news_success})\n"
                f"└ За неделю: {news_week}\n\n"
                "👥 **Персонал:**\n"
                f"├ Модераторов: {moderators_count}\n"
                f"└ Пользователей AGNKS: {agnks_count}"
            )
            
            await message.answer(text, parse_mode="Markdown", reply_markup=await get_admin_menu())
            
    except Exception as e:
        logger.error(f"Не удалось получить статистику: {e}", exc_info=True)
        await message.answer("Произошла ошибка при получении статистики.")

@dp.message(F.text == "📁 Экспорт данных")
async def admin_export_handler(message: types.Message):
    if not await is_admin(message.from_user.id):
        return
    
    builder = InlineKeyboardBuilder()
    builder.button(text="📋 Вопросы", callback_data="export_questions")
    builder.button(text="👤 Физ. лица", callback_data="export_physical")
    builder.button(text="🏢 Юр. лица", callback_data="export_legal")
    builder.button(text="📰 Новости", callback_data="export_news")
    builder.button(text="⬅️ Назад", callback_data="admin_back")
    builder.adjust(1, 2, 1, 1)
    
    await message.answer(
        "Выберите данные для экспорта:",
        reply_markup=builder.as_markup()
    )

@dp.callback_query(F.data == "export_news")
async def export_news_handler(callback: types.CallbackQuery):
    logger.info(f"Админ {callback.from_user.id} экспортирует публикации новостей")
    await callback.message.edit_text(
        "Подготовка файла с публикациями новостей...",
        reply_markup=None
    )
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            publications = await conn.fetch("SELECT * FROM news_publications ORDER BY created_at DESC")
            
            if not publications:
                await callback.message.answer("Нет публикаций для экспорта.")
                return
            
            pub_data = []
            for p in publications:
                pub_data.append({
                    'id': p['id'],
                    'user_id': p['user_id'],
                    'username': p['username'] or '',
                    'title': p['title'],
                    'content': p['content'],
                    'site_news_id': p['site_news_id'] or '',
                    'status': p['status'],
                    'error_message': p['error_message'] or '',
                    'created_at': p['created_at'],
                    'published_at': p['published_at'] or ''
                })
            
            csv_path = await export_to_csv(pub_data, "news_publications.csv")
            
            if csv_path:
                await callback.message.answer_document(
                    BufferedInputFile.from_file(csv_path, filename="news_publications.csv"),
                    caption="Экспорт публикаций новостей завершен."
                )
            else:
                await callback.message.answer("Не удалось экспортировать данные.")
                
    except Exception as e:
        logger.error(f"Не удалось экспортировать публикации новостей: {e}", exc_info=True)
        await callback.message.answer("Произошла ошибка при экспорте.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "export_questions")
async def export_questions_handler(callback: types.CallbackQuery):
    logger.info(f"Админ {callback.from_user.id} экспортирует вопросы")
    await callback.message.edit_text(
        "Подготовка файла с вопросами...",
        reply_markup=None
    )
    
    csv_path = await export_questions_to_csv()
    if not csv_path:
        await callback.message.answer("Не удалось экспортировать вопросы.")
        return
    
    try:
        await callback.message.answer_document(
            BufferedInputFile.from_file(csv_path, filename="questions.csv"),
            caption="Экспорт вопросов завершен."
        )
    except Exception as e:
        logger.error(f"Не удалось отправить экспорт вопросов: {e}", exc_info=True)
        await callback.message.answer("Не удалось отправить файл с вопросами.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "export_physical")
async def export_physical_handler(callback: types.CallbackQuery):
    logger.info(f"Админ {callback.from_user.id} экспортирует договоры физ. лиц")
    await callback.message.edit_text(
        "Подготовка файла с договорами физ. лиц...",
        reply_markup=None
    )
    
    csv_path = await export_physical_contracts_to_csv()
    if not csv_path:
        await callback.message.answer("Не удалось экспортировать договоры физ. лиц.")
        return
    
    try:
        await callback.message.answer_document(
            BufferedInputFile.from_file(csv_path, filename="physical_contracts.csv"),
            caption="Экспорт договоров физ. лиц завершен."
        )
    except Exception as e:
        logger.error(f"Не удалось отправить экспорт договоров физ. лиц: {e}", exc_info=True)
        await callback.message.answer("Не удалось отправить файл с договорами физ. лиц.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "export_legal")
async def export_legal_handler(callback: types.CallbackQuery):
    logger.info(f"Админ {callback.from_user.id} экспортирует договоры юр. лиц")
    await callback.message.edit_text(
        "Подготовка файла с договорами юр. лиц...",
        reply_markup=None
    )
    
    csv_path = await export_legal_contracts_to_csv()
    if not csv_path:
        await callback.message.answer("Не удалось экспортировать договоры юр. лиц.")
        return
    
    try:
        await callback.message.answer_document(
            BufferedInputFile.from_file(csv_path, filename="legal_contracts.csv"),
            caption="Экспорт договоров юр. лиц завершен."
        )
    except Exception as e:
        logger.error(f"Не удалось отправить экспорт договоров юр. лиц: {e}", exc_info=True)
        await callback.message.answer("Не удалось отправить файл с договорами юр. лиц.")
    finally:
        await callback.answer()

@dp.message(F.text == "🗃 Управление хранилищем")
async def admin_storage_handler(message: types.Message):
    if not await is_admin(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    await message.delete()  # удаляем сообщение пользователя
    await send_storage_menu(message.from_user.id, message.chat.id)

async def send_storage_menu(user_id: int, chat_id: int, message_to_edit: Optional[types.Message] = None):
    """Отправляет или редактирует сообщение с меню хранилища"""
    try:
        disk_usage = shutil.disk_usage("/")
        total_gb = disk_usage.total / (1024 ** 3)
        used_gb = disk_usage.used / (1024 ** 3)
        free_gb = disk_usage.free / (1024 ** 3)
        
        log_files = {}
        log_dir = "logs"
        if os.path.exists(log_dir):
            for f in os.listdir(log_dir):
                fp = os.path.join(log_dir, f)
                if os.path.isfile(fp):
                    size_mb = os.path.getsize(fp) / (1024 * 1024)
                    modified = datetime.fromtimestamp(os.path.getmtime(fp))
                    log_files[f] = {
                        'size': size_mb,
                        'modified': modified.strftime("%d.%m.%Y %H:%M")
                    }
        
        temp_files = 0
        temp_size = 0
        if os.path.exists("temp"):
            for f in os.listdir("temp"):
                fp = os.path.join("temp", f)
                if os.path.isfile(fp):
                    temp_files += 1
                    temp_size += os.path.getsize(fp)
        temp_size_mb = temp_size / (1024 ** 2)
        
        backup_files = 0
        backup_size = 0
        if os.path.exists("backups"):
            for f in os.listdir("backups"):
                fp = os.path.join("backups", f)
                if os.path.isfile(fp):
                    backup_files += 1
                    backup_size += os.path.getsize(fp)
        backup_size_mb = backup_size / (1024 ** 2)
        
        text = (
            "🗃 **Управление хранилищем**\n\n"
            "💽 **Дисковое пространство:**\n"
            f"├ Всего: {total_gb:.2f} GB\n"
            f"├ Использовано: {used_gb:.2f} GB\n"
            f"└ Свободно: {free_gb:.2f} GB\n\n"
            "📄 **Лог-файлы:**\n"
        )
        
        for name, info in log_files.items():
            text += f"├ {name}: {info['size']:.2f} MB ({info['modified']})\n"
        
        text += (
            f"\n📁 **Временные файлы:** {temp_files} ({temp_size_mb:.2f} MB)\n"
            f"📀 **Бэкапы:** {backup_files} ({backup_size_mb:.2f} MB, храним последние 5)\n\n"
            "Выберите действие:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="📋 Просмотреть логи", callback_data="view_logs_menu")
        builder.button(text="👥 Список пользователей", callback_data="view_users_menu")
        builder.button(text="🧹 Очистить временные", callback_data="clean_temp")
        builder.button(text="📀 Очистить старые бэкапы", callback_data="clean_backups")
        builder.button(text="🔄 Создать бэкап сейчас", callback_data="create_backup_now")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(1, 2, 1, 1, 1)  # изменён adjust для новой кнопки
        
        if message_to_edit and hasattr(message_to_edit, 'edit_text'):
            await message_to_edit.edit_text(
                text,
                parse_mode="Markdown",
                reply_markup=builder.as_markup()
            )
        else:
            await bot.send_message(
                chat_id,
                text,
                parse_mode="Markdown",
                reply_markup=builder.as_markup()
            )
        
    except Exception as e:
        logger.error(f"Ошибка получения информации о хранилище: {e}", exc_info=True)
        await bot.send_message(chat_id, "❌ Произошла ошибка при получении информации о хранилище.")

# ==================== ПРОСМОТР СПИСКА ПОЛЬЗОВАТЕЛЕЙ ====================

async def get_users_with_filter(filter_type: str, period_days: int = None) -> List[Dict]:
    """
    Получить список пользователей с фильтрацией.
    filter_type: 'registered' или 'activity'
    period_days: None - все, 7, 30, 90
    """
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        if period_days is None:
            # Без фильтра по дате
            if filter_type == 'registered':
                rows = await conn.fetch(
                    "SELECT user_id, username, first_name, last_name, registered_at, last_activity "
                    "FROM users ORDER BY registered_at DESC"
                )
            else:
                rows = await conn.fetch(
                    "SELECT user_id, username, first_name, last_name, registered_at, last_activity "
                    "FROM users ORDER BY last_activity DESC"
                )
        else:
            # С фильтром по количеству дней
            if filter_type == 'registered':
                rows = await conn.fetch(
                    "SELECT user_id, username, first_name, last_name, registered_at, last_activity "
                    "FROM users WHERE registered_at > CURRENT_DATE - $1 * INTERVAL '1 day' "
                    "ORDER BY registered_at DESC",
                    period_days
                )
            else:
                rows = await conn.fetch(
                    "SELECT user_id, username, first_name, last_name, registered_at, last_activity "
                    "FROM users WHERE last_activity > CURRENT_DATE - $1 * INTERVAL '1 day' "
                    "ORDER BY last_activity DESC",
                    period_days
                )
        return [dict(row) for row in rows]

def format_user_list(users: List[Dict], page: int, per_page: int = 20) -> tuple[str, int]:
    """Форматирует список пользователей для вывода. Возвращает (текст, общее количество страниц)"""
    if not users:
        return "❌ Нет пользователей, соответствующих фильтру.", 0
    
    total = len(users)
    total_pages = (total + per_page - 1) // per_page
    start = page * per_page
    end = min(start + per_page, total)
    users_page = users[start:end]
    
    text = f"👥 <b>Список пользователей</b> (всего: {total})\n\n"
    for u in users_page:
        name = u.get('first_name', '') or ''
        if u.get('last_name'):
            name += ' ' + u['last_name']
        name = name.strip() or 'Без имени'
        username = f"@{u['username']}" if u.get('username') else "нет username"
        registered = u['registered_at'].strftime('%d.%m.%Y') if u['registered_at'] else "?"
        last_activity = u['last_activity'].strftime('%d.%m.%Y %H:%M') if u['last_activity'] else "?"
        text += (
            f"🆔 {u['user_id']} – {html.escape(name)} ({html.escape(username)})\n"
            f"   📅 Регистрация: {html.escape(registered)} | 📆 Активность: {html.escape(last_activity)}\n\n"
        )
    
    return text, total_pages

@dp.callback_query(F.data == "view_users_menu")
async def view_users_menu(callback: types.CallbackQuery):
    """Показывает меню выбора фильтра для списка пользователей"""
    builder = InlineKeyboardBuilder()
    builder.button(text="📅 За всё время", callback_data="view_users:registered:all:0")
    builder.button(text="📅 За последние 7 дней", callback_data="view_users:registered:7:0")
    builder.button(text="📅 За последние 30 дней", callback_data="view_users:registered:30:0")
    builder.button(text="📅 За последние 90 дней", callback_data="view_users:registered:90:0")
    builder.button(text="🕒 Активность за всё время", callback_data="view_users:activity:all:0")
    builder.button(text="🕒 Активность за 7 дней", callback_data="view_users:activity:7:0")
    builder.button(text="🕒 Активность за 30 дней", callback_data="view_users:activity:30:0")
    builder.button(text="🕒 Активность за 90 дней", callback_data="view_users:activity:90:0")
    builder.button(text="📁 Экспорт в CSV", callback_data="export_users:registered:all")
    builder.button(text="⬅️ Назад", callback_data="admin_storage_back")
    builder.adjust(2, 2, 2, 2, 1, 1)
    
    await callback.message.edit_text(
        "🔍 **Выберите фильтр для списка пользователей:**\n\n"
        "• **Регистрация** – по дате регистрации\n"
        "• **Активность** – по дате последней активности",
        parse_mode="Markdown",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("view_users:"))
async def view_users_handler(callback: types.CallbackQuery):
    """Показывает список пользователей с пагинацией"""
    parts = callback.data.split(":")
    if len(parts) != 4:
        await callback.message.edit_text(
            text,
            parse_mode="HTML",
            reply_markup=builder.as_markup()
        )
    
    filter_type = parts[1]  # registered или activity
    period = parts[2]       # all или число дней
    page = int(parts[3])
    
    period_days = None if period == "all" else int(period)
    
    await callback.answer("⏳ Загрузка списка пользователей...")
    
    try:
        users = await get_users_with_filter(filter_type, period_days)
        text, total_pages = format_user_list(users, page)
        
        builder = InlineKeyboardBuilder()
        
        # Навигация
        if page > 0:
            builder.button(text="⬅️ Предыдущая", callback_data=f"view_users:{filter_type}:{period}:{page-1}")
        if page < total_pages - 1:
            builder.button(text="➡️ Следующая", callback_data=f"view_users:{filter_type}:{period}:{page+1}")
        
        # Кнопка экспорта
        builder.button(text="📁 Экспорт в CSV", callback_data=f"export_users:{filter_type}:{period}")
        builder.button(text="🔄 Другой фильтр", callback_data="view_users_menu")
        builder.button(text="⬅️ Назад", callback_data="admin_storage_back")
        builder.adjust(2, 1, 1) if total_pages > 1 else builder.adjust(1, 1)
        
        await callback.message.edit_text(
            text,
            parse_mode="HTML",  # Исправлено: ранее было "Markdown"
            reply_markup=builder.as_markup()
        )
    except Exception as e:
        logger.error(f"Ошибка при получении списка пользователей: {e}", exc_info=True)
        await callback.message.edit_text(
            "❌ Произошла ошибка при загрузке списка пользователей.",
            reply_markup=InlineKeyboardBuilder().button(text="⬅️ Назад", callback_data="admin_storage_back").as_markup()
        )
    await callback.answer()

@dp.callback_query(F.data.startswith("export_users:"))
async def export_users_handler(callback: types.CallbackQuery):
    """Экспорт списка пользователей в CSV"""
    parts = callback.data.split(":")
    if len(parts) != 3:
        await callback.answer("❌ Неверные данные", show_alert=True)
        return
    
    filter_type = parts[1]
    period = parts[2]
    period_days = None if period == "all" else int(period)
    
    await callback.answer("⏳ Подготовка файла...")
    
    try:
        users = await get_users_with_filter(filter_type, period_days)
        if not users:
            await callback.message.answer("❌ Нет пользователей для экспорта.")
            return
        
        # Подготовка данных для CSV
        data = []
        for u in users:
            name = u.get('first_name', '') or ''
            if u.get('last_name'):
                name += ' ' + u['last_name']
            data.append({
                'user_id': u['user_id'],
                'username': u.get('username', ''),
                'full_name': name.strip(),
                'registered_at': u['registered_at'].strftime('%d.%m.%Y %H:%M:%S') if u['registered_at'] else '',
                'last_activity': u['last_activity'].strftime('%d.%m.%Y %H:%M:%S') if u['last_activity'] else ''
            })
        
        csv_path = await export_to_csv(data, f"users_{filter_type}_{period}.csv")
        if csv_path:
            with open(csv_path, 'rb') as f:
                await callback.message.answer_document(
                    BufferedInputFile(f.read(), filename=f"users_{filter_type}_{period}.csv"),
                    caption=f"Экспорт пользователей ({filter_type}, {period}) завершен."
                )
        else:
            await callback.message.answer("❌ Не удалось создать файл экспорта.")
    except Exception as e:
        logger.error(f"Ошибка экспорта пользователей: {e}", exc_info=True)
        await callback.message.answer("❌ Произошла ошибка при экспорте.")
    await callback.answer()


# ==================== ПРОСМОТР ЛОГОВ (с пагинацией) ====================

@dp.callback_query(F.data == "view_logs_menu")
async def view_logs_menu_handler(callback: types.CallbackQuery):
    """Меню выбора лог-файла"""
    builder = InlineKeyboardBuilder()
    
    log_files = {
        "bot.log": "📋 Основной лог",
        "errors.log": "❌ Ошибки",
        "debug.log": "🔍 Отладка",
        "requests.log": "📨 Запросы",
        "database.log": "🗄️ База данных",
        "security.log": "🔒 Безопасность"
    }
    
    for filename, description in log_files.items():
        if os.path.exists(f"logs/{filename}"):
            size = os.path.getsize(f"logs/{filename}") / 1024
            builder.button(
                text=f"{description} ({size:.1f} KB)",
                callback_data=f"view_log:{filename}:0"  # начальный offset = 0
            )
    
    builder.button(text="🧹 Очистить все логи", callback_data="clean_all_logs")
    builder.button(text="⬅️ Назад", callback_data="admin_storage_back")
    builder.adjust(1)
    
    await callback.message.edit_text(
        "📋 **Выберите лог-файл для просмотра:**\n\n"
        "Будут показаны последние 100 строк. Используйте кнопки навигации для загрузки предыдущих страниц.",
        parse_mode="Markdown",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("view_log:"))
async def view_log_handler(callback: types.CallbackQuery):
    """Показывает страницу лога с заданным offset (количество строк от конца)"""
    parts = callback.data.split(":")
    if len(parts) < 2:
        await callback.answer("❌ Неверные данные", show_alert=True)
        return
    
    filename = parts[1]
    offset = int(parts[2]) if len(parts) > 2 else 0
    page_size = 100  # количество строк на странице
    
    filepath = f"logs/{filename}"
    
    if not os.path.exists(filepath):
        await callback.answer("❌ Файл не найден", show_alert=True)
        return
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
        
        total_lines = len(all_lines)
        # Определяем начальный индекс для выборки (с конца)
        start_idx = max(0, total_lines - page_size - offset)
        end_idx = total_lines - offset
        if start_idx >= end_idx:
            start_idx = max(0, end_idx - page_size)
        
        selected = all_lines[start_idx:end_idx]
        
        log_text = "".join(selected)
        file_size = os.path.getsize(filepath) / 1024
        
        # Формируем текст с информацией о странице
        page_info = f"Строки {start_idx+1}-{end_idx} из {total_lines}"
        text = (
            f"📄 **{filename}**\n"
            f"Размер: {file_size:.1f} KB\n"
            f"{page_info}\n\n"
            f"```\n{log_text}\n```"
        )
        
        # Обрезаем, если слишком длинно (Telegram лимит 4096 символов)
        if len(text) > 4096:
            # Пробуем урезать лог
            max_log_len = 4096 - len(text) + len(log_text) - 500
            log_text = log_text[-max_log_len:]
            text = (
                f"📄 **{filename}**\n"
                f"Размер: {file_size:.1f} KB\n"
                f"{page_info} (обрезано до последних {max_log_len} символов)\n\n"
                f"```\n{log_text}\n```"
            )
        
        # Кнопки навигации
        builder = InlineKeyboardBuilder()
        
        # Кнопка "Предыдущая страница" (если есть строки до текущего блока)
        if start_idx > 0:
            new_offset = offset + page_size
            builder.button(text="⬅️ Предыдущие", callback_data=f"view_log:{filename}:{new_offset}")
        
        # Кнопка "Следующая страница" (если есть строки после текущего блока)
        if end_idx < total_lines:
            new_offset = max(0, offset - page_size)
            builder.button(text="➡️ Следующие", callback_data=f"view_log:{filename}:{new_offset}")
        
        builder.button(text="🔄 Обновить", callback_data=f"view_log:{filename}:{offset}")
        builder.button(text="🧹 Очистить", callback_data=f"clean_log:{filename}")
        builder.button(text="⬅️ Назад к списку", callback_data="view_logs_menu")
        builder.adjust(2, 1, 1)  # два ряда навигации, затем обновить/очистить, затем назад
        
        # Пытаемся отредактировать сообщение, игнорируем ошибку "message is not modified"
        try:
            await callback.message.edit_text(
                text,
                parse_mode="Markdown",
                reply_markup=builder.as_markup()
            )
        except TelegramBadRequest as e:
            if "message is not modified" in str(e):
                # Сообщение уже такое же, ничего не делаем
                logger.debug(f"Сообщение не изменено при просмотре лога {filename}")
                await callback.answer("Нет изменений")
            else:
                raise
        
    except Exception as e:
        logger.error(f"Ошибка чтения лога {filename}: {e}", exc_info=True)
        await callback.answer("❌ Ошибка чтения файла", show_alert=True)
    
    await callback.answer()

@dp.callback_query(F.data.startswith("clean_log:"))
async def clean_log_handler(callback: types.CallbackQuery):
    filename = callback.data.replace("clean_log:", "")
    filepath = f"logs/{filename}"
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# Лог очищен {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        logger.info(f"🧹 Лог {filename} очищен администратором {callback.from_user.id}")
        await callback.answer("✅ Лог очищен", show_alert=False)
        
        await view_log_handler(callback)
    except Exception as e:
        logger.error(f"Ошибка очистки лога {filename}: {e}")
        await callback.answer("❌ Ошибка очистки", show_alert=True)

@dp.callback_query(F.data == "clean_all_logs")
async def clean_all_logs_handler(callback: types.CallbackQuery):
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Да, очистить всё", callback_data="confirm_clean_all_logs")
    builder.button(text="❌ Нет, отмена", callback_data="view_logs_menu")
    
    await callback.message.edit_text(
        "⚠️ **Вы уверены, что хотите очистить все лог-файлы?**\n"
        "Это действие нельзя отменить.",
        parse_mode="Markdown",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@dp.callback_query(F.data == "confirm_clean_all_logs")
async def confirm_clean_all_logs_handler(callback: types.CallbackQuery):
    cleaned = 0
    for filename in os.listdir("logs"):
        filepath = os.path.join("logs", filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"# Лог очищен {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                cleaned += 1
            except Exception as e:
                logger.error(f"Ошибка очистки {filename}: {e}")
    
    logger.info(f"🧹 Очищено {cleaned} лог-файлов администратором {callback.from_user.id}")
    await callback.message.edit_text(
        f"✅ Очищено {cleaned} лог-файлов.",
        reply_markup=InlineKeyboardBuilder().button(
            text="⬅️ Назад", callback_data="view_logs_menu"
        ).as_markup()
    )
    await callback.answer()

@dp.callback_query(F.data == "admin_storage_back")
async def admin_storage_back_handler(callback: types.CallbackQuery):
    await callback.message.delete()
    await send_storage_menu(callback.from_user.id, callback.message.chat.id)

@dp.callback_query(F.data == "create_backup_now")
async def create_backup_now_handler(callback: types.CallbackQuery):
    await callback.message.edit_text("⏳ Создание резервной копии...")
    
    success = await create_db_backup()
    
    if success:
        await callback.message.edit_text(
            "✅ Резервная копия успешно создана!",
            reply_markup=InlineKeyboardBuilder().button(
                text="⬅️ Назад", callback_data="admin_storage_back"
            ).as_markup()
        )
    else:
        await callback.message.edit_text(
            "❌ Ошибка при создании резервной копии.",
            reply_markup=InlineKeyboardBuilder().button(
                text="⬅️ Назад", callback_data="admin_storage_back"
            ).as_markup()
        )
    
    await callback.answer()

@dp.callback_query(F.data == "clean_temp")
async def clean_temp_handler(callback: types.CallbackQuery):
    logger.info(f"Админ {callback.from_user.id} очищает временные файлы")
    try:
        await cleanup_temp_files()
        await callback.message.edit_text(
            "✅ Временные файлы очищены.",
            reply_markup=InlineKeyboardBuilder().button(
                text="⬅️ Назад", callback_data="admin_storage_back"
            ).as_markup()
        )
    except Exception as e:
        logger.error(f"Не удалось очистить временные файлы: {e}", exc_info=True)
        await callback.message.answer("❌ Не удалось очистить временные файлы.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "clean_backups")
async def clean_backups_handler(callback: types.CallbackQuery):
    logger.info(f"Админ {callback.from_user.id} очищает старые бэкапы")
    try:
        removed = await rotate_backups(5)
        await callback.message.edit_text(
            f"✅ Удалено {removed} старых бэкапов. Оставлены последние 5.",
            reply_markup=InlineKeyboardBuilder().button(
                text="⬅️ Назад", callback_data="admin_storage_back"
            ).as_markup()
        )
    except Exception as e:
        logger.error(f"Не удалось очистить бэкапы: {e}", exc_info=True)
        await callback.message.answer("❌ Не удалось очистить бэкапы.")
    finally:
        await callback.answer()

# ==================== УПРАВЛЕНИЕ ПЕРСОНАЛОМ (без истории действий) ====================

async def get_moderators(active_only: bool = True) -> List[Dict]:
    """Получить список модераторов из БД"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        if active_only:
            rows = await conn.fetch("SELECT * FROM moderators WHERE is_active = TRUE ORDER BY added_at")
        else:
            rows = await conn.fetch("SELECT * FROM moderators ORDER BY added_at")
        return [dict(row) for row in rows]

async def get_agnks_users(active_only: bool = True) -> List[Dict]:
    """Получить список AGNKS пользователей из БД"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        if active_only:
            rows = await conn.fetch("SELECT * FROM agnks_users WHERE is_active = TRUE ORDER BY added_at")
        else:
            rows = await conn.fetch("SELECT * FROM agnks_users ORDER BY added_at")
        return [dict(row) for row in rows]

async def add_moderator(user_id: int, username: str = None, admin_id: int = None) -> bool:
    """Добавить модератора"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        try:
            await conn.execute("""
                INSERT INTO moderators (user_id, username, added_by) 
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id) DO UPDATE SET 
                    is_active = TRUE,
                    username = EXCLUDED.username,
                    added_by = EXCLUDED.added_by,
                    added_at = CURRENT_TIMESTAMP
                """,
                user_id, username, admin_id
            )
            
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, target_username, details)
                VALUES ($1, $2, $3, $4, $5)
                """,
                admin_id, 'add_moderator', user_id, username, f'Добавлен модератор {username or user_id}'
            )
            
            logger.info(f"➕ Модератор {user_id} добавлен")
            return True
        except Exception as e:
            logger.error(f"Ошибка добавления модератора: {e}")
            return False

async def remove_moderator(user_id: int, admin_id: int = None) -> bool:
    """Удалить модератора (мягкое удаление)"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        try:
            await conn.execute(
                "UPDATE moderators SET is_active = FALSE WHERE user_id = $1",
                user_id
            )
            
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, details)
                VALUES ($1, $2, $3, $4)
                """,
                admin_id, 'remove_moderator', user_id, f'Удалён модератор {user_id}'
            )
            
            logger.info(f"➖ Модератор {user_id} удалён")
            return True
        except Exception as e:
            logger.error(f"Ошибка удаления модератора: {e}")
            return False

async def add_agnks_user(user_id: int, username: str = None, admin_id: int = None) -> bool:
    """Добавить AGNKS пользователя"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        try:
            await conn.execute("""
                INSERT INTO agnks_users (user_id, username, added_by) 
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id) DO UPDATE SET 
                    is_active = TRUE,
                    username = EXCLUDED.username,
                    added_by = EXCLUDED.added_by,
                    added_at = CURRENT_TIMESTAMP
                """,
                user_id, username, admin_id
            )
            
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, target_username, details)
                VALUES ($1, $2, $3, $4, $5)
                """,
                admin_id, 'add_agnks', user_id, username, f'Добавлен AGNKS {username or user_id}'
            )
            
            logger.info(f"➕ AGNKS {user_id} добавлен")
            return True
        except Exception as e:
            logger.error(f"Ошибка добавления AGNKS: {e}")
            return False

async def remove_agnks_user(user_id: int, admin_id: int = None) -> bool:
    """Удалить AGNKS пользователя"""
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        try:
            await conn.execute(
                "UPDATE agnks_users SET is_active = FALSE WHERE user_id = $1",
                user_id
            )
            
            await conn.execute("""
                INSERT INTO admin_actions (admin_id, action, target_id, details)
                VALUES ($1, $2, $3, $4)
                """,
                admin_id, 'remove_agnks', user_id, f'Удалён AGNKS {user_id}'
            )
            
            logger.info(f"➖ AGNKS {user_id} удалён")
            return True
        except Exception as e:
            logger.error(f"Ошибка удаления AGNKS: {e}")
            return False

# --- Функция отображения меню (используется повторно) ---

async def show_staff_menu(update: Union[types.Message, types.CallbackQuery]):
    """Показывает меню управления персоналом (без проверки прав, т.к. вызывается из защищённых мест)"""
    moderators = await get_moderators()
    agnks_users = await get_agnks_users()
    
    text = (
        "<b>👥 Управление персоналом</b>\n\n"
        f"<b>👤 Модераторы</b> ({len(moderators)}):\n"
    )
    
    for mod in moderators:
        user_id = html.escape(str(mod['user_id']))
        username = html.escape(f"@{mod['username']}" if mod['username'] else "без username")
        added = html.escape(mod['added_at'].strftime("%d.%m.%Y") if mod['added_at'] else "неизвестно")
        text += f"├ {user_id} - {username} (добавлен: {added})\n"
    
    text += f"\n<b>⛽ AGNKS пользователи</b> ({len(agnks_users)}):\n"
    for agnks in agnks_users:
        user_id = html.escape(str(agnks['user_id']))
        username = html.escape(f"@{agnks['username']}" if agnks['username'] else "без username")
        added = html.escape(agnks['added_at'].strftime("%d.%m.%Y") if agnks['added_at'] else "неизвестно")
        text += f"├ {user_id} - {username} (добавлен: {added})\n"
    
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Добавить модератора", callback_data="add_moderator")
    builder.button(text="➖ Удалить модератора", callback_data="remove_moderator")
    builder.button(text="➕ Добавить AGNKS", callback_data="add_agnks")
    builder.button(text="➖ Удалить AGNKS", callback_data="remove_agnks")
    builder.button(text="🔄 Синхронизировать с .env", callback_data="sync_from_env")
    builder.button(text="⬅️ Назад", callback_data="admin_back")
    builder.adjust(2, 2, 1, 1)  # убрана кнопка истории действий
    
    markup = builder.as_markup()
    
    if isinstance(update, types.CallbackQuery):
        await update.message.edit_text(text, parse_mode="HTML", reply_markup=markup)
    else:
        await update.answer(text, parse_mode="HTML", reply_markup=markup)

# --- Основной вход (проверка прав) ---

@dp.message(F.text == "👥 Управление персоналом")
async def manage_staff_handler(message: types.Message):
    if not await is_admin(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    await show_staff_menu(message)

# --- Возврат из подменю (без проверки прав) ---

@dp.callback_query(F.data == "back_to_staff")
async def back_to_staff_handler(callback: types.CallbackQuery):
    await show_staff_menu(callback)

# --- Отмена действия (просто удаляем сообщение) ---

@dp.callback_query(F.data == "cancel_admin_action")
async def cancel_admin_action(callback: types.CallbackQuery, state: FSMContext):
    await state.clear()
    await callback.message.edit_text("❌ Действие отменено.")
    await callback.answer()

# --- Добавление модератора ---

@dp.callback_query(F.data == "add_moderator")
async def add_moderator_start(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.edit_text(
        "Отправьте ID пользователя, которого хотите сделать модератором.\n"
        "Пользователь должен хотя бы раз написать боту (нажать /start).",
        reply_markup=InlineKeyboardBuilder().button(
            text="❌ Отмена", callback_data="cancel_admin_action"
        ).as_markup()
    )
    await state.set_state(AdminStates.waiting_for_moderator_id)
    await callback.answer()

@dp.message(AdminStates.waiting_for_moderator_id)
async def add_moderator_process(message: types.Message, state: FSMContext):
    try:
        user_id = int(message.text.strip())
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT username FROM users WHERE user_id = $1",
                user_id
            )
        
        if not user:
            await message.answer(
                "❌ Пользователь с таким ID не найден в базе.\n"
                "Он должен хотя бы раз написать боту."
            )
            await state.clear()
            return
        
        success = await add_moderator(user_id, user['username'], message.from_user.id)
        
        if success:
            await message.answer(f"✅ Пользователь {user_id} (@{user['username']}) добавлен в модераторы.")
        else:
            await message.answer("❌ Ошибка при добавлении модератора.")
        
        await state.clear()
        
    except ValueError:
        await message.answer("❌ Пожалуйста, отправьте числовой ID.")

# --- Удаление модератора ---

@dp.callback_query(F.data == "remove_moderator")
async def remove_moderator_start(callback: types.CallbackQuery):
    moderators = await get_moderators()
    
    if not moderators:
        await callback.message.edit_text(
            "Нет активных модераторов.",
            reply_markup=InlineKeyboardBuilder().button(
                text="◀️ Назад", callback_data="back_to_staff"
            ).as_markup()
        )
        await callback.answer()
        return
    
    builder = InlineKeyboardBuilder()
    for mod in moderators[:10]:
        username = mod['username'] or 'без username'
        builder.button(
            text=f"❌ {mod['user_id']} (@{username})",
            callback_data=f"confirm_remove_moderator:{mod['user_id']}"
        )
    builder.button(text="◀️ Назад", callback_data="back_to_staff")
    builder.adjust(1)
    
    await callback.message.edit_text(
        "Выберите модератора для удаления:",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("confirm_remove_moderator:"))
async def confirm_remove_moderator(callback: types.CallbackQuery):
    user_id = int(callback.data.split(":")[1])
    
    success = await remove_moderator(user_id, callback.from_user.id)
    
    if success:
        await callback.message.edit_text(
            f"✅ Модератор {user_id} удалён.",
            reply_markup=InlineKeyboardBuilder().button(
                text="◀️ Назад", callback_data="back_to_staff"
            ).as_markup()
        )
    else:
        await callback.message.edit_text(
            "❌ Ошибка при удалении.",
            reply_markup=InlineKeyboardBuilder().button(
                text="◀️ Назад", callback_data="back_to_staff"
            ).as_markup()
        )
    
    await callback.answer()

# --- Добавление AGNKS ---

@dp.callback_query(F.data == "add_agnks")
async def add_agnks_start(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.edit_text(
        "Отправьте ID пользователя для добавления в группу AGNKS:",
        reply_markup=InlineKeyboardBuilder().button(
            text="❌ Отмена", callback_data="cancel_admin_action"
        ).as_markup()
    )
    await state.set_state(AdminStates.waiting_for_agnks_id)
    await callback.answer()

@dp.message(AdminStates.waiting_for_agnks_id)
async def add_agnks_process(message: types.Message, state: FSMContext):
    try:
        user_id = int(message.text.strip())
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT username FROM users WHERE user_id = $1",
                user_id
            )
        
        if not user:
            await message.answer("❌ Пользователь не найден.")
            await state.clear()
            return
        
        success = await add_agnks_user(user_id, user['username'], message.from_user.id)
        
        if success:
            await message.answer(f"✅ Пользователь {user_id} добавлен в AGNKS.")
        else:
            await message.answer("❌ Ошибка при добавлении.")
        
        await state.clear()
        
    except ValueError:
        await message.answer("❌ Неверный ID.")

# --- Удаление AGNKS ---

@dp.callback_query(F.data == "remove_agnks")
async def remove_agnks_start(callback: types.CallbackQuery):
    agnks_users = await get_agnks_users()
    
    if not agnks_users:
        await callback.message.edit_text(
            "Нет активных AGNKS пользователей.",
            reply_markup=InlineKeyboardBuilder().button(
                text="◀️ Назад", callback_data="back_to_staff"
            ).as_markup()
        )
        await callback.answer()
        return
    
    builder = InlineKeyboardBuilder()
    for user in agnks_users[:10]:
        username = user['username'] or 'без username'
        builder.button(
            text=f"❌ {user['user_id']} (@{username})",
            callback_data=f"confirm_remove_agnks:{user['user_id']}"
        )
    builder.button(text="◀️ Назад", callback_data="back_to_staff")
    builder.adjust(1)
    
    await callback.message.edit_text(
        "Выберите пользователя для удаления из AGNKS:",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("confirm_remove_agnks:"))
async def confirm_remove_agnks(callback: types.CallbackQuery):
    user_id = int(callback.data.split(":")[1])
    
    success = await remove_agnks_user(user_id, callback.from_user.id)
    
    if success:
        await callback.message.edit_text(
            f"✅ Пользователь {user_id} удалён из AGNKS.",
            reply_markup=InlineKeyboardBuilder().button(
                text="◀️ Назад", callback_data="back_to_staff"
            ).as_markup()
        )
    else:
        await callback.message.edit_text(
            "❌ Ошибка при удалении.",
            reply_markup=InlineKeyboardBuilder().button(
                text="◀️ Назад", callback_data="back_to_staff"
            ).as_markup()
        )
    
    await callback.answer()

# --- Синхронизация с .env ---

@dp.callback_query(F.data == "sync_from_env")
async def sync_from_env_handler(callback: types.CallbackQuery):
    added = 0
    for mod_id in config.MODERATOR_IDS:
        if await add_moderator(mod_id, admin_id=callback.from_user.id):
            added += 1
    
    for agnks_id in config.AGNKS_IDS:
        if await add_agnks_user(agnks_id, admin_id=callback.from_user.id):
            added += 1
    
    await callback.message.edit_text(
        f"✅ Синхронизация завершена.\n"
        f"Добавлено/обновлено пользователей: {added}",
        reply_markup=InlineKeyboardBuilder().button(
            text="◀️ Назад", callback_data="back_to_staff"
        ).as_markup()
    )
    await callback.answer()

# ==================== УПРАВЛЕНИЕ УВЕДОМЛЕНИЯМИ (с поддержкой AGNKS) ====================

@dp.message(F.text == "🔔 Управление уведомлениями")
async def admin_notifications_handler(message: types.Message):
    if not await is_admin(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    await update_notifications_message(message)

async def update_notifications_message(update: Union[types.Message, types.CallbackQuery]):
    """Показывает текущие настройки уведомлений и клавиатуру для их изменения."""
    # Получаем текущие значения
    admin_questions = await is_notification_enabled('notify_admin_questions')
    admin_contracts = await is_notification_enabled('notify_admin_contracts')
    admin_errors = await is_notification_enabled('notify_admin_errors')
    admin_news = await is_notification_enabled('notify_admin_news')
    
    mod_questions = await is_notification_enabled('notify_moderators_questions')
    mod_contracts = await is_notification_enabled('notify_moderators_contracts')
    mod_news_from_admin = await is_notification_enabled('notify_moderators_news_from_admin')
    mod_news_from_agnks = await is_notification_enabled('notify_moderators_news_from_agnks')
    
    # Настройки для AGNKS
    agnks_news_from_admin = await is_notification_enabled('notify_agnks_news_from_admin')
    agnks_news_from_agnks = await is_notification_enabled('notify_agnks_news_from_agnks')
    
    text = (
        "🔔 **Настройки уведомлений**\n\n"
        "📌 **Для администратора:**\n"
        f"1. Новые вопросы: {'✅ вкл' if admin_questions else '❌ выкл'}\n"
        f"2. Новые договоры: {'✅ вкл' if admin_contracts else '❌ выкл'}\n"
        f"3. Ошибки системы: {'✅ вкл' if admin_errors else '❌ выкл'}\n"
        f"4. Новые новости: {'✅ вкл' if admin_news else '❌ выкл'}\n\n"
        "📌 **Для модераторов:**\n"
        f"5. Новые вопросы: {'✅ вкл' if mod_questions else '❌ выкл'}\n"
        f"6. Новые договоры: {'✅ вкл' if mod_contracts else '❌ выкл'}\n"
        f"7. Новые новости (от администратора): {'✅ вкл' if mod_news_from_admin else '❌ выкл'}\n"
        f"8. Новые новости (от AGNKS): {'✅ вкл' if mod_news_from_agnks else '❌ выкл'}\n\n"
        "📌 **Для AGNKS:**\n"
        f"9. Новости от администратора: {'✅ вкл' if agnks_news_from_admin else '❌ выкл'}\n"
        f"10. Новости от AGNKS: {'✅ вкл' if agnks_news_from_agnks else '❌ выкл'}\n\n"
        "Выберите параметр для изменения:"
    )
    
    builder = InlineKeyboardBuilder()
    # Админ
    builder.button(text="1️⃣", callback_data="toggle_admin_questions")
    builder.button(text="2️⃣", callback_data="toggle_admin_contracts")
    builder.button(text="3️⃣", callback_data="toggle_admin_errors")
    builder.button(text="4️⃣", callback_data="toggle_admin_news")
    # Модераторы
    builder.button(text="5️⃣", callback_data="toggle_mod_questions")
    builder.button(text="6️⃣", callback_data="toggle_mod_contracts")
    builder.button(text="7️⃣", callback_data="toggle_mod_news_from_admin")
    builder.button(text="8️⃣", callback_data="toggle_mod_news_from_agnks")
    # AGNKS
    builder.button(text="9️⃣", callback_data="toggle_agnks_news_from_admin")
    builder.button(text="🔟", callback_data="toggle_agnks_news_from_agnks")
    # Навигация
    builder.button(text="⬅️ Назад", callback_data="admin_back")
    builder.adjust(4, 4, 2, 1)  # 4 админа, 4 модератора, 2 AGNKS, 1 назад
    
    markup = builder.as_markup()
    
    if isinstance(update, types.CallbackQuery):
        await update.message.edit_text(text, parse_mode="Markdown", reply_markup=markup)
    else:
        await update.answer(text, parse_mode="Markdown", reply_markup=markup)

# --- Обработчики переключения для администратора ---

@dp.callback_query(F.data == "toggle_admin_questions")
async def toggle_admin_questions(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_admin_questions')

@dp.callback_query(F.data == "toggle_admin_contracts")
async def toggle_admin_contracts(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_admin_contracts')

@dp.callback_query(F.data == "toggle_admin_errors")
async def toggle_admin_errors(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_admin_errors')

@dp.callback_query(F.data == "toggle_admin_news")
async def toggle_admin_news(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_admin_news')

# --- Обработчики переключения для модераторов ---

@dp.callback_query(F.data == "toggle_mod_questions")
async def toggle_mod_questions(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_moderators_questions')

@dp.callback_query(F.data == "toggle_mod_contracts")
async def toggle_mod_contracts(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_moderators_contracts')

@dp.callback_query(F.data == "toggle_mod_news_from_admin")
async def toggle_mod_news_from_admin(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_moderators_news_from_admin')

@dp.callback_query(F.data == "toggle_mod_news_from_agnks")
async def toggle_mod_news_from_agnks(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_moderators_news_from_agnks')

# --- Обработчики переключения для AGNKS ---

@dp.callback_query(F.data == "toggle_agnks_news_from_admin")
async def toggle_agnks_news_from_admin(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_agnks_news_from_admin')

@dp.callback_query(F.data == "toggle_agnks_news_from_agnks")
async def toggle_agnks_news_from_agnks(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_agnks_news_from_agnks')

# --- Общая функция переключения ---

async def toggle_notification_setting(callback: types.CallbackQuery, setting_key: str):
    """Переключает значение настройки уведомления в БД и обновляет сообщение."""
    current = await is_notification_enabled(setting_key)
    new_value = not current
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
            "ON CONFLICT (key) DO UPDATE SET value = $2",
            setting_key, '1' if new_value else '0'
        )
    
    # Инвалидируем кэш
    redis_client.delete(f'notification:{setting_key}')
    
    # Обновляем отображаемое меню
    await update_notifications_message(callback)
    await callback.answer(f"Уведомления {'включены' if new_value else 'выключены'}")

# ==================== УПРАВЛЕНИЕ КНОПКАМИ ====================

async def get_buttons_management_text_and_markup():
    """Возвращает текст и клавиатуру для управления кнопками"""
    consultation = await is_button_enabled('button_consultation')
    roi = await is_button_enabled('button_roi')
    experience = await is_button_enabled('button_experience')
    contract = await is_button_enabled('button_contract')
    add_news = await is_button_enabled('button_add_news')
    questions = await is_button_enabled('button_unanswered_questions')
    contracts = await is_button_enabled('button_view_contracts')
    delayed = await is_button_enabled('button_delayed_messages')
    publish_to_group = await is_button_enabled('button_publish_to_group')
    
    text = (
        "🛠 Управление кнопками:\n\n"
        "📌 Для всех пользователей:\n"
        f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
        f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
        f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
        f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
        "📌 Для группы АГНКС:\n"
        f"5. 📰 Добавить новость на сайт: {'вкл' if add_news else 'выкл'}\n\n"
        "📌 Для модераторов:\n"
        f"6. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
        f"7. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
        f"8. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
        "📌 Дополнительно:\n"
        f"9. 📢 Публиковать новости в Telegram-группе: {'вкл' if publish_to_group else 'выкл'}\n\n"
        "Выберите кнопку для изменения:"
    )
    
    builder = InlineKeyboardBuilder()
    builder.button(text="1️⃣", callback_data="toggle_button_consultation")
    builder.button(text="2️⃣", callback_data="toggle_button_roi")
    builder.button(text="3️⃣", callback_data="toggle_button_experience")
    builder.button(text="4️⃣", callback_data="toggle_button_contract")
    builder.button(text="5️⃣", callback_data="toggle_button_add_news")
    builder.button(text="6️⃣", callback_data="toggle_button_unanswered_questions")
    builder.button(text="7️⃣", callback_data="toggle_button_view_contracts")
    builder.button(text="8️⃣", callback_data="toggle_button_delayed_messages")
    builder.button(text="9️⃣", callback_data="toggle_button_publish_to_group")
    builder.button(text="⬅️ Назад", callback_data="admin_back")
    builder.adjust(4, 1, 3, 1, 1)  # 4+1+3+1+1
    
    return text, builder.as_markup()

@dp.message(F.text == "🛠 Управление кнопками")
async def admin_buttons_handler(message: types.Message):
    """Обработчик команды 'Управление кнопками' — отправляет новое сообщение с меню"""
    if not await is_admin(message.from_user.id):
        return
    
    text, markup = await get_buttons_management_text_and_markup()
    await message.answer(text, reply_markup=markup)

async def update_buttons_message(callback: types.CallbackQuery):
    """Обновляет существующее сообщение с меню управления кнопками"""
    text, markup = await get_buttons_management_text_and_markup()
    try:
        await callback.message.edit_text(text, reply_markup=markup)
    except TelegramBadRequest as e:
        if "message is not modified" in str(e):
            await callback.answer("Состояние не изменилось")
        else:
            raise

@dp.callback_query(F.data == "toggle_button_consultation")
async def toggle_button_consultation_handler(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_consultation')

@dp.callback_query(F.data == "toggle_button_roi")
async def toggle_button_roi_handler(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_roi')

@dp.callback_query(F.data == "toggle_button_experience")
async def toggle_button_experience_handler(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_experience')

@dp.callback_query(F.data == "toggle_button_contract")
async def toggle_button_contract_handler(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_contract')

@dp.callback_query(F.data == "toggle_button_add_news")
async def toggle_button_add_news_handler(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_add_news')

@dp.callback_query(F.data == "toggle_button_unanswered_questions")
async def toggle_button_unanswered_questions(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_unanswered_questions')
		
@dp.callback_query(F.data == "toggle_button_view_contracts")
async def toggle_button_view_contracts(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_view_contracts')

@dp.callback_query(F.data == "toggle_button_delayed_messages")
async def toggle_button_delayed_messages(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_delayed_messages')

@dp.callback_query(F.data == "toggle_button_publish_to_group")
async def toggle_button_publish_to_group(callback: types.CallbackQuery):
    await toggle_button(callback, 'button_publish_to_group')

async def toggle_button(callback: types.CallbackQuery, button_key: str):
    logger.info(f"Админ {callback.from_user.id} переключает кнопку {button_key}")
    try:
        current = await is_button_enabled(button_key)
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                button_key, '1' if new_value else '0'
            )
        
        redis_client.delete(f'button:{button_key}')
        
        # Обновляем текущее сообщение
        await update_buttons_message(callback)
        await callback.answer(f"Кнопка {'включена' if new_value else 'выключена'}")
        
    except Exception as e:
        logger.error(f"Не удалось переключить кнопку {button_key}: {e}", exc_info=True)
        await callback.answer("Не удалось изменить состояние кнопки.", show_alert=True)

# ==================== УПРАВЛЕНИЕ ОТЛОЖЕННЫМИ СООБЩЕНИЯМИ ====================

@dp.message(F.text == "⏱ Создать отложенное сообщение")
async def create_delayed_message(message: types.Message, state: FSMContext):
    if not await is_moderator(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    builder = ReplyKeyboardBuilder()
    builder.button(text="📝 Только текст")
    builder.button(text="🖼 Только фото")
    builder.button(text="📝+🖼 Текст с фото")
    builder.button(text="❌ Отменить")
    builder.adjust(2, 1, 1)
    
    await message.answer(
        "Выберите тип сообщения:",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(DelayedMessageStates.waiting_for_content)

@dp.message(F.text == "⏱ Управление отлож. сообщениями")
async def manage_delayed_messages(message: types.Message):
    if not await is_admin(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        messages = await conn.fetch(
            "SELECT * FROM delayed_messages "
            "WHERE status IN ('pending', 'approved') "
            "ORDER BY send_time LIMIT 10"
        )
        
        if not messages:
            await message.answer("Нет отложенных сообщений для управления.")
            return
        
        for msg in messages:
            text = (
                f"📨 Отложенное сообщение ID: {msg['id']}\n"
                f"Статус: {msg['status']}\n"
                f"Тип: {msg['content_type']}\n"
                f"Время отправки: {msg['send_time'].strftime('%d.%m.%Y %H:%M')}\n"
                f"Получатели: {msg['recipient_type']}"
            )
            
            if msg['text_content']:
                text += f"\n\nТекст: {msg['text_content']}"
            
            builder = InlineKeyboardBuilder()
            if msg['status'] == 'pending':
                builder.button(text="✅ Одобрить", callback_data=f"approve_msg_{msg['id']}")
                builder.button(text="❌ Отклонить", callback_data=f"reject_msg_{msg['id']}")
            else:
                builder.button(text="🚫 Отменить отправку", callback_data=f"block_msg_{msg['id']}")
                builder.button(text="👁️ Скрыть", callback_data=f"hide_msg_{msg['id']}")
                builder.adjust(2, 1)
            
            try:
                if msg['photo_path'] and os.path.exists(msg['photo_path']):
                    with open(msg['photo_path'], 'rb') as photo:
                        photo_bytes = photo.read()
                    input_file = BufferedInputFile(photo_bytes, filename="photo.jpg")
                    await message.answer_photo(
                        input_file,
                        caption=text,
                        reply_markup=builder.as_markup()
                    )
                else:
                    await message.answer(
                        text,
                        reply_markup=builder.as_markup()
                    )
            except Exception as e:
                logger.error(f"Не удалось показать сообщение {msg['id']}: {e}", exc_info=True)
                await message.answer(
                    f"Ошибка при отображении сообщения {msg['id']}",
                    reply_markup=builder.as_markup()
                )

# ==================== УПРАВЛЕНИЕ ЦЕНАМИ ====================

@dp.message(F.text == "⛽ Управление ценами")
async def manage_prices(message: types.Message):
    if not await is_admin(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            prices = await conn.fetch(
                "SELECT key, value FROM bot_settings WHERE key LIKE '%price%' OR key LIKE '%installation%'"
            )
        
        price_dict = {p['key']: p['value'] for p in prices}
        
        text = (
            "⛽ Текущие настройки цен:\n\n"
            f"1. Цена бензина: {price_dict.get('gasoline_price', '2.5')} руб/л\n"
            f"2. Цена ДТ: {price_dict.get('diesel_price', '2.46')} руб/л\n"
            f"3. Цена КПГ: {price_dict.get('cng_price', '1.0')} руб/м³\n\n"
            f"4. Переоборудование бензин (до 3.5т): {price_dict.get('gasoline_installation_light', '3000')} руб\n"
            f"5. Переоборудование бензин (свыше 3.5т): {price_dict.get('gasoline_installation_heavy', '5000')} руб\n"
            f"6. Переоборудование ДТ: {price_dict.get('diesel_installation', '15000')} руб\n\n"
            "Выберите параметр для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣ Бензин", callback_data="edit_price_gasoline_price")
        builder.button(text="2️⃣ ДТ", callback_data="edit_price_diesel_price")
        builder.button(text="3️⃣ КПГ", callback_data="edit_price_cng_price")
        builder.button(text="4️⃣ Переоб. бензин (легк.)", callback_data="edit_price_gasoline_installation_light")
        builder.button(text="5️⃣ Переоб. бензин (тяж.)", callback_data="edit_price_gasoline_installation_heavy")
        builder.button(text="6️⃣ Переоб. ДТ", callback_data="edit_price_diesel_installation")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(3, 3, 1)
        
        await message.answer(text, reply_markup=builder.as_markup())
        
    except Exception as e:
        logger.error(f"Не удалось получить цены: {e}")
        await message.answer("Произошла ошибка при получении цен")

class PriceEditStates(StatesGroup):
    waiting_for_price = State()
    price_key = State()

@dp.callback_query(F.data.startswith("edit_price_"))
async def edit_price_handler(callback: types.CallbackQuery, state: FSMContext):
    price_key = callback.data.split("_", 2)[2]
    friendly_name = {
        'gasoline_price': "бензин",
        'diesel_price': "ДТ",
        'cng_price': "КПГ",
        'gasoline_installation_light': "переоборудование бензин (до 3.5т)",
        'gasoline_installation_heavy': "переоборудование бензин (свыше 3.5т)",
        'diesel_installation': "переоборудование ДТ"
    }.get(price_key, price_key)
    
    await state.set_state(PriceEditStates.waiting_for_price)
    await state.update_data(price_key=price_key)
    
    await callback.message.answer(
        f"Введите новое значение для {friendly_name}:",
        reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
    )
    await callback.answer()

@dp.message(PriceEditStates.waiting_for_price, F.text == "❌ Отменить")
async def cancel_price_edit(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Изменение цены отменено.",
        reply_markup=await get_admin_menu()
    )

@dp.message(PriceEditStates.waiting_for_price)
async def process_new_price(message: types.Message, state: FSMContext):
    try:
        data = await state.get_data()
        price_key = data['price_key']
        new_price = float(message.text.replace(",", "."))
        
        if new_price <= 0:
            raise ValueError("Цена должна быть положительной")
            
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                price_key, str(new_price)
            )
        
        await message.answer(
            f"✅ Цена успешно обновлена!",
            reply_markup=await get_admin_menu()
        )
        await state.clear()
        
    except ValueError:
        await message.answer("❌ Пожалуйста, введите корректное положительное число")

# ==================== ОБРАБОТЧИКИ ОТЛОЖЕННЫХ СООБЩЕНИЙ ====================

@dp.message(StateFilter(DelayedMessageStates), F.text == "❌ Отменить")
async def cancel_delayed_message(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Создание отложенного сообщения отменено.",
        reply_markup=await get_moderator_menu()
    )

@dp.message(DelayedMessageStates.waiting_for_text, F.text != "❌ Отменить")
async def process_text_content(message: types.Message, state: FSMContext):
    await state.update_data(text_content=message.text)
    await message.answer(
        "Введите время отправки в формате ДД.ММ.ГГГГ ЧЧ:ММ:",
        reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
    )
    await state.set_state(DelayedMessageStates.waiting_for_time)

@dp.message(DelayedMessageStates.waiting_for_content)
async def process_content_type(message: types.Message, state: FSMContext):
    if message.text == "📝 Только текст":
        await state.update_data(content_type="text")
        await message.answer(
            "Введите текст сообщения:",
            reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
        )
        await state.set_state(DelayedMessageStates.waiting_for_text)
    elif message.text in ["🖼 Только фото", "📝+🖼 Текст с фото"]:
        content_type = "photo" if message.text == "🖼 Только фото" else "photo_with_text"
        await state.update_data(content_type=content_type)
        await message.answer(
            "Отправьте фото:",
            reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
        )
        await state.set_state(DelayedMessageStates.waiting_for_photo)

@dp.message(DelayedMessageStates.waiting_for_photo, F.photo)
async def process_photo(message: types.Message, state: FSMContext):
    data = await state.get_data()
    
    photo_path = f"temp/delayed_photos/{message.photo[-1].file_id}.jpg"
    
    try:
        file_info = await bot.get_file(message.photo[-1].file_id)
        await bot.download_file(file_info.file_path, destination=photo_path)
        
        await state.update_data(photo_path=photo_path)
        
        if data['content_type'] == 'photo_with_text':
            await message.answer(
                "Теперь введите текст сообщения:",
                reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
            )
            await state.set_state(DelayedMessageStates.waiting_for_text)
        else:
            await message.answer(
                "Введите время отправки в формате ДД.ММ.ГГГГ ЧЧ:ММ:",
                reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
            )
            await state.set_state(DelayedMessageStates.waiting_for_time)
            
    except Exception as e:
        logger.error(f"Не удалось загрузить фото: {e}", exc_info=True)
        await message.answer("Не удалось сохранить фото. Попробуйте еще раз.")
		
@dp.message(DelayedMessageStates.waiting_for_photo)
async def process_not_photo(message: types.Message):
    await message.answer("Пожалуйста, отправьте фото или отмените действие.")
		
@dp.message(DelayedMessageStates.waiting_for_time, F.text != "❌ Отменить")
async def process_time(message: types.Message, state: FSMContext):
    try:
        send_time = datetime.strptime(message.text, "%d.%m.%Y %H:%M")
        if send_time < datetime.now():
            raise ValueError("Время должно быть в будущем")
        
        await state.update_data(send_time=send_time.isoformat())
        
        builder = ReplyKeyboardBuilder()
        builder.button(text="👥 Всем пользователям")
        builder.button(text="🛡 Только модераторам")
        builder.button(text="👤 Конкретному пользователю")
        builder.button(text="❌ Отменить")
        builder.adjust(2, 1, 1)
        
        await message.answer(
            "Выберите получателей:",
            reply_markup=builder.as_markup(resize_keyboard=True)
        )
        await state.set_state(DelayedMessageStates.waiting_for_recipients)
    except ValueError as e:
        await message.answer(f"❌ {str(e)}. Пожалуйста, введите время в формате ДД.ММ.ГГГГ ЧЧ:ММ")

@dp.message(DelayedMessageStates.waiting_for_recipients, F.text != "❌ Отменить")
async def process_recipients(message: types.Message, state: FSMContext):
    if message.text == "👤 Конкретному пользователю":
        await message.answer(
            "Введите ID пользователя:",
            reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
        )
        await state.set_state(DelayedMessageStates.waiting_for_user_id)
    else:
        recipient_type = "all" if message.text == "👥 Всем пользователям" else "moderators"
        await state.update_data(recipient_type=recipient_type, recipient_id=None)
        await confirm_and_save_message(message, state)

@dp.message(DelayedMessageStates.waiting_for_user_id, F.text != "❌ Отменить")
async def process_user_id(message: types.Message, state: FSMContext):
    try:
        user_id = int(message.text)
        await state.update_data(recipient_type="specific", recipient_id=user_id)
        await confirm_and_save_message(message, state)
    except ValueError:
        await message.answer("❌ Неверный ID пользователя. Пожалуйста, введите числовой ID.")

async def confirm_and_save_message(message: types.Message, state: FSMContext):
    data = await state.get_data()
	
    send_time = datetime.fromisoformat(data['send_time'])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message_id = await conn.fetchval(
            """
            INSERT INTO delayed_messages (
                content_type, text_content, photo_path, send_time, status, 
                recipient_type, recipient_id, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            """,
            data['content_type'],
            data.get('text_content'),
            data.get('photo_path'),
            send_time,
            'pending',
            data['recipient_type'],
            data.get('recipient_id'),
            message.from_user.id
        )
    
    notify_text = f"📨 Новое отложенное сообщение (ID: {message_id})\n\n"
    
    if data.get('text_content'):
        notify_text += f"📝 Текст: {data['text_content']}\n\n"
    
    notify_text += (
        f"⏰ Время отправки: {datetime.fromisoformat(data['send_time']).strftime('%d.%m.%Y %H:%M')}\n"
        f"👥 Получатели: "
    )
    
    if data['recipient_type'] == 'all':
        notify_text += "все пользователи"
    elif data['recipient_type'] == 'moderators':
        notify_text += "модераторы"
    else:
        notify_text += f"пользователь с ID {data['recipient_id']}"
    
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Одобрить", callback_data=f"approve_msg_{message_id}")
    builder.button(text="❌ Отклонить", callback_data=f"reject_msg_{message_id}")
    builder.button(text="👁️ Скрыть", callback_data=f"hide_msg_{message_id}")
    builder.adjust(2,1)
    
    try:
        if data.get('photo_path') and os.path.exists(data['photo_path']):
            with open(data['photo_path'], 'rb') as photo:
                photo_bytes = photo.read()
            input_file = BufferedInputFile(photo_bytes, filename="photo.jpg")
            
            # Отправляем уведомление всем админам
            tasks = []
            for admin_id in config.ADMIN_IDS:
                tasks.append(bot.send_photo(admin_id, input_file, caption=notify_text, reply_markup=builder.as_markup()))
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            tasks = []
            for admin_id in config.ADMIN_IDS:
                tasks.append(bot.send_message(admin_id, notify_text, reply_markup=builder.as_markup()))
            await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        logger.error(f"Не удалось отправить уведомление админам: {e}", exc_info=True)
    
    await message.answer(
        "Сообщение создано и отправлено на подтверждение администратору.",
        reply_markup=await get_moderator_menu()
    )
    await state.clear()

# ==================== ОБРАБОТЧИКИ ДЕЙСТВИЙ АДМИНИСТРАТОРА ====================

@dp.callback_query(F.data.startswith("hide_msg_"))
async def hide_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    try:
        await callback.message.delete()
        await callback.answer("Сообщение скрыто", show_alert=False)
    except Exception as e:
        logger.error(f"Не удалось скрыть сообщение: {e}", exc_info=True)
        await callback.answer("Не удалось скрыть сообщение", show_alert=True)
		
@dp.callback_query(F.data.startswith("approve_msg_"))
async def approve_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message_data = await conn.fetchrow(
            "SELECT * FROM delayed_messages WHERE id = $1",
            message_id
        )
        
        await conn.execute(
            "UPDATE delayed_messages SET status = 'approved', approved_by = $1, approved_at = CURRENT_TIMESTAMP WHERE id = $2",
            callback.from_user.id,
            message_id
        )
    
    try:
        await callback.message.delete()
    except Exception as e:
        logger.error(f"Не удалось удалить сообщение: {e}", exc_info=True)
    await callback.answer("✅ Сообщение одобрено", show_alert=False)
    
    if message_data['created_by']:
        try:
            await bot.send_message(
                message_data['created_by'],
                f"✅ Ваше отложенное сообщение (ID: {message_id}) было одобрено администратором."
            )
        except Exception as e:
            logger.error(f"Не удалось уведомить модератора: {e}", exc_info=True)
    
    await callback.message.answer(
        f"✅ Сообщение {message_id} одобрено и будет отправлено в указанное время."
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("reject_msg_"))
async def reject_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message_data = await conn.fetchrow(
            "SELECT * FROM delayed_messages WHERE id = $1",
            message_id
        )
        
        if message_data.get('photo_path'):
            try:
                os.remove(message_data['photo_path'])
            except:
                pass
        
        await conn.execute(
            "UPDATE delayed_messages SET status = 'rejected' WHERE id = $1",
            message_id
        )
    
    try:
        await callback.message.delete()
    except Exception as e:
        logger.error(f"Не удалось удалить сообщение: {e}", exc_info=True)
    await callback.answer("❌ Сообщение отклонено", show_alert=False)
	
    if message_data['created_by']:
        try:
            await bot.send_message(
                message_data['created_by'],
                f"❌ Ваше отложенное сообщение (ID: {message_id}) было отклонено администратором."
            )
        except Exception as e:
            logger.error(f"Не удалось уведомить модератора: {e}", exc_info=True)
    
    await callback.message.answer(
        f"❌ Сообщение {message_id} отклонено."
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("block_msg_"))
async def block_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message_data = await conn.fetchrow(
            "SELECT * FROM delayed_messages WHERE id = $1",
            message_id
        )
        
        await conn.execute(
            "UPDATE delayed_messages SET status = 'blocked' WHERE id = $1",
            message_id
        )
    
    try:
        await callback.message.delete()
    except Exception as e:
        logger.error(f"Не удалось удалить сообщение: {e}", exc_info=True)
    await callback.answer("🚫 Отправка отменена", show_alert=False)
    
    if message_data['created_by']:
        try:
            await bot.send_message(
                message_data['created_by'],
                f"🚫 Отправка вашего отложенного сообщения (ID: {message_id}) была отменена администратором."
            )
        except Exception as e:
            logger.error(f"Не удалось уведомить модератора: {e}", exc_info=True)
    
    await callback.message.answer(
        f"🚫 Отправка сообщения {message_id} отменена."
    )
    await callback.answer()

# ==================== НАЗАД В МЕНЮ ====================

@dp.callback_query(F.data == "admin_back")
async def admin_back_handler(callback: types.CallbackQuery):
    logger.info(f"Админ {callback.from_user.id} вернулся в админ-панель")
    await callback.message.edit_text(
        "Возвращаемся в админ-панель",
        reply_markup=None
    )
    await callback.message.answer(
        "Админ-панель:",
        reply_markup=await get_admin_menu()
    )
    await callback.answer()

@dp.message(F.text == "⬅️ Главное меню")
async def back_to_main_handler(message: types.Message):
    logger.info(f"Пользователь {message.from_user.id} вернулся в главное меню")
    await message.answer(
        "Главное меню:",
        reply_markup=await get_main_menu(message.from_user.id)
    )

# ==================== ФОНОВЫЕ ЗАДАЧИ ====================

async def send_scheduled_messages():
    while True:
        try:
            pool = await get_db_connection()
            async with pool.acquire() as conn:
                messages = await conn.fetch(
                    "SELECT * FROM delayed_messages "
                    "WHERE status = 'approved' AND send_time <= CURRENT_TIMESTAMP"
                )
                
                for msg in messages:
                    try:
                        if not msg['text_content'] and msg['content_type'] in ['text', 'photo_with_text']:
                            await conn.execute(
                                "UPDATE delayed_messages SET status = 'failed' WHERE id = $1",
                                msg['id']
                            )
                            continue
                            
                        if msg['recipient_type'] == 'all':
                            users = await conn.fetch("SELECT user_id FROM users")
                            recipient_ids = [u['user_id'] for u in users]
                        elif msg['recipient_type'] == 'moderators':
                            recipient_ids = [mod['user_id'] for mod in await get_moderators()] + config.ADMIN_IDS
                        else:
                            recipient_ids = [msg['recipient_id']]
                        
                        success = True
                        for user_id in recipient_ids:
                            try:
                                if msg['content_type'] == 'text' and msg['text_content']:
                                    await bot.send_message(user_id, msg['text_content'])
                                elif msg['content_type'] == 'photo' and msg['photo_path']:
                                    with open(msg['photo_path'], 'rb') as photo_file:
                                        photo_bytes = photo_file.read()
                                    input_file = BufferedInputFile(photo_bytes, filename="photo.jpg")
                                    await bot.send_photo(user_id, input_file)
                                elif msg['content_type'] == 'photo_with_text' and msg['photo_path'] and msg['text_content']:
                                    with open(msg['photo_path'], 'rb') as photo_file:
                                        photo_bytes = photo_file.read()
                                    input_file = BufferedInputFile(photo_bytes, filename="photo.jpg")
                                    await bot.send_photo(user_id, input_file, caption=msg['text_content'])
                            except Exception as e:
                                logger.error(f"Не удалось отправить сообщение {msg['id']} пользователю {user_id}: {e}", exc_info=True)
                                success = False
                                break
                        
                        if success:
                            await conn.execute(
                                "UPDATE delayed_messages SET status = 'sent' WHERE id = $1",
                                msg['id']
                            )
                            if msg.get('photo_path'):
                                try:
                                    os.remove(msg['photo_path'])
                                except:
                                    pass
                        else:
                            attempts = msg.get('attempts', 0) + 1
                            if attempts >= 3:
                                await conn.execute(
                                    "UPDATE delayed_messages SET status = 'failed' WHERE id = $1",
                                    msg['id']
                                )
                            else:
                                await conn.execute(
                                    "UPDATE delayed_messages SET attempts = $1 WHERE id = $2",
                                    attempts,
                                    msg['id']
                                )
                    except Exception as e:
                        logger.error(f"Ошибка обработки сообщения {msg['id']}: {e}", exc_info=True)
                        await conn.execute(
                            "UPDATE delayed_messages SET status = 'failed' WHERE id = $1",
                            msg['id']
                        )
            
            await asyncio.sleep(60)
        except Exception as e:
            logger.error(f"Ошибка в send_scheduled_messages: {e}", exc_info=True)
            await asyncio.sleep(300)

async def scheduled_backups():
    while True:
        await asyncio.sleep(24 * 60 * 60)  # 24 часа
        await create_db_backup()

# ==================== ОБРАБОТЧИК ОШИБОК ====================

@dp.error()
async def error_handler(event: types.ErrorEvent):
    logger.error(f"💥 Необработанная ошибка: {event.exception}", exc_info=True)
    
    if isinstance(event.update, types.Message):
        await event.update.answer("Произошла непредвиденная ошибка. Пожалуйста, попробуйте позже.")

# ==================== STARTUP И SHUTDOWN ====================

async def on_startup(dispatcher: Dispatcher):
    logger.info("🚀 Бот запускается...")
    
    asyncio.create_task(send_scheduled_messages())
    
    await init_db()
    
    for mod_id in config.MODERATOR_IDS:
        await add_moderator(mod_id, admin_id=config.ADMIN_IDS[0] if config.ADMIN_IDS else None)
    
    for agnks_id in config.AGNKS_IDS:
        await add_agnks_user(agnks_id, admin_id=config.ADMIN_IDS[0] if config.ADMIN_IDS else None)
    
    await create_db_backup()
    asyncio.create_task(scheduled_backups())
    
    await notify_admins("🚀 Бот запущен и готов к работе", EMOJI_INFO)
    
    bot_info = await bot.me()
    logger.info(f"🤖 Bot: @{bot_info.username}")
    logger.info(f"👑 Admin IDs: {config.ADMIN_IDS}")
    logger.info(f"👥 Moderators: {len(config.MODERATOR_IDS)} в .env, всего в БД: {len(await get_moderators())}")
    logger.info(f"⛽ AGNKS: {len(config.AGNKS_IDS)} в .env, всего в БД: {len(await get_agnks_users())}")
    logger.info("="*80)

async def on_shutdown(dispatcher: Dispatcher):
    logger.info("🛑 Бот выключается...")
    await notify_admins("🛑 Бот выключается", EMOJI_WARNING)
    await bot.session.close()
    if db_pool:
        await db_pool.close()
    redis_client.close()
    logger.info("✅ Соединения закрыты")

# ==================== ГЛАВНАЯ ФУНКЦИЯ ====================

async def main():
    logger.info("="*80)
    logger.info("🚀 ЗАПУСК БОТА")
    logger.info("="*80)
    
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)
    
    try:
        await dp.start_polling(
            bot,
            allowed_updates=['message', 'callback_query', 'inline_query'],
            timeout=30
        )
    except Exception as e:
        logger.critical(f"💥 Критическая ошибка при запуске: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Бот остановлен пользователем")
    except Exception as e:
        logger.critical(f"💥 Критическая ошибка: {e}", exc_info=True)
