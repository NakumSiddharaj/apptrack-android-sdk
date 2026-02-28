#!/bin/bash
# ============================================================
# AppTrack MMP — PostgreSQL Persistent Storage
# Users, Apps, Campaigns → PostgreSQL (permanent)
# Clicks, Dedup, RateLimit, Sessions → Redis (fast cache)
# ============================================================
set -e
BASE="/opt/attribution/backend/app"
echo "🚀 Migrating to PostgreSQL persistent storage..."

# ── Install deps ─────────────────────────────────────────────
echo "📦 Installing dependencies..."
docker exec attribution_backend pip install asyncpg sqlalchemy[asyncio] bcrypt "redis[asyncio]" -q 2>/dev/null || \
pip install asyncpg "sqlalchemy[asyncio]" bcrypt "redis[asyncio]" --break-system-packages -q

# ── models/models.py ─────────────────────────────────────────
cat > $BASE/models/models.py << 'PYEOF'
from sqlalchemy import Column, String, Boolean, Text, DateTime, Float, BigInteger, Index
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func
import uuid
from app.core.database import Base

class User(Base):
    __tablename__ = "users"
    id         = Column(String(20), primary_key=True)
    email      = Column(String(255), unique=True, nullable=False, index=True)
    name       = Column(String(255), nullable=False)
    password   = Column(String(255), nullable=False)
    role       = Column(String(20), default="customer")
    plan       = Column(String(20), default="free")
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class App(Base):
    __tablename__ = "apps"
    bundle_id      = Column(String(255), primary_key=True)
    name           = Column(String(255), nullable=False)
    api_key        = Column(String(100), unique=True, nullable=False, index=True)
    play_store_url = Column(Text, default="")
    category       = Column(String(100), default="")
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())

class Campaign(Base):
    __tablename__ = "campaigns"
    id           = Column(String(36), primary_key=True)
    name         = Column(String(255), nullable=False)
    app_id       = Column(String(255), nullable=False, index=True)
    source       = Column(String(100), default="pubscale")
    offer_id     = Column(String(100), nullable=True, index=True)
    play_store_url = Column(Text, default="")
    postback_url = Column(Text, nullable=True)
    events       = Column(JSONB, default={})
    tracking_url = Column(Text, nullable=True)
    is_active    = Column(Boolean, default=True)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())
    updated_at   = Column(DateTime(timezone=True), onupdate=func.now())

class Install(Base):
    __tablename__ = "installs"
    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    app_id       = Column(String(255), nullable=False, index=True)
    uid          = Column(String(100), nullable=False, index=True)
    device_id    = Column(String(255), nullable=False)
    advertising_id = Column(String(100), nullable=True)
    clickid      = Column(String(255), nullable=True, index=True)
    campaign_id  = Column(String(36), nullable=True, index=True)
    country      = Column(String(10), nullable=True)
    device_model = Column(String(100), nullable=True)
    os_version   = Column(String(50), nullable=True)
    app_version  = Column(String(50), nullable=True)
    network      = Column(String(20), nullable=True)
    carrier      = Column(String(100), nullable=True)
    brand        = Column(String(100), nullable=True)
    ip_address   = Column(String(45), nullable=True)
    is_debug     = Column(Boolean, default=False)
    ivc          = Column(Boolean, nullable=True)
    server_time  = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    __table_args__ = (
        Index("idx_install_app_time", "app_id", "server_time"),
        Index("idx_install_campaign", "campaign_id", "server_time"),
    )

class Event(Base):
    __tablename__ = "events"
    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    app_id       = Column(String(255), nullable=False, index=True)
    uid          = Column(String(100), nullable=False, index=True)
    device_id    = Column(String(255), nullable=False)
    event_name   = Column(String(100), nullable=False, index=True)
    event_uuid   = Column(String(100), unique=True, nullable=False)
    event_value  = Column(Float, nullable=True)
    data         = Column(JSONB, default={})
    clickid      = Column(String(255), nullable=True)
    campaign_id  = Column(String(36), nullable=True, index=True)
    is_debug     = Column(Boolean, default=False)
    server_time  = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    __table_args__ = (
        Index("idx_event_app_time",  "app_id", "server_time"),
        Index("idx_event_app_name",  "app_id", "event_name"),
        Index("idx_event_campaign",  "campaign_id", "server_time"),
    )

class FraudLog(Base):
    __tablename__ = "fraud_logs"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    app_id     = Column(String(255), nullable=False, index=True)
    device_id  = Column(String(255), nullable=False)
    uid        = Column(String(100), nullable=True)
    reason     = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=True)
    server_time = Column(DateTime(timezone=True), server_default=func.now(), index=True)
PYEOF

# ── core/database.py ─────────────────────────────────────────
cat > $BASE/core/database.py << 'PYEOF'
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=20,
    max_overflow=40,
    pool_pre_ping=True,
    pool_recycle=3600,
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False,
)

class Base(DeclarativeBase):
    pass

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[DB] ✅ Tables ready")

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
PYEOF

# ── api/auth.py ──────────────────────────────────────────────
cat > $BASE/api/auth.py << 'PYEOF'
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from app.core.database import get_db
from app.core.config import settings
from app.core.security import require_api_key, hash_password, verify_password, get_redis
from app.models.models import User
import secrets, json, jwt

router   = APIRouter(tags=["Auth"])
JWT_SECRET = settings.SECRET_KEY
JWT_ALGO   = "HS256"
JWT_EXPIRE = 7 * 24 * 3600

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str

class LoginRequest(BaseModel):
    email: str
    password: str

def make_token(user_id, role, plan):
    return jwt.encode(
        {"sub": user_id, "role": role, "plan": plan,
         "exp": datetime.utcnow() + timedelta(seconds=JWT_EXPIRE)},
        JWT_SECRET, algorithm=JWT_ALGO
    )

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")

@router.post("/auth/login")
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user   = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password):
        raise HTTPException(401, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(403, "Account disabled")
    # Rehash if old sha256
    import hashlib
    if user.password == hashlib.sha256(body.password.encode()).hexdigest():
        await db.execute(update(User).where(User.id == user.id).values(password=hash_password(body.password)))
    return {"token": make_token(user.id, user.role, user.plan),
            "role": user.role, "plan": user.plan, "name": user.name}

@router.get("/auth/me")
async def me(authorization: str = Header(...), db: AsyncSession = Depends(get_db)):
    payload = decode_token(authorization.replace("Bearer ", ""))
    result  = await db.execute(select(User).where(User.id == payload["sub"]))
    user    = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    return {"id": user.id, "email": user.email, "name": user.name,
            "role": user.role, "plan": user.plan, "is_active": user.is_active,
            "created_at": str(user.created_at)}

@router.post("/auth/register")
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db),
                   api_key: str = Depends(require_api_key)):
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Email already exists")
    user = User(
        id=secrets.token_urlsafe(12), email=body.email,
        name=body.name, password=hash_password(body.password),
    )
    db.add(user)
    return {"status": "created", "user_id": user.id, "email": user.email}

@router.get("/users")
async def list_users(db: AsyncSession = Depends(get_db),
                     api_key: str = Depends(require_api_key)):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users  = result.scalars().all()
    return {"users": [{"id": u.id, "email": u.email, "name": u.name,
                       "role": u.role, "plan": u.plan, "is_active": u.is_active,
                       "created_at": str(u.created_at)} for u in users]}

@router.put("/users/{user_id}/plan")
async def upgrade_plan(user_id: str, plan: str, db: AsyncSession = Depends(get_db),
                       api_key: str = Depends(require_api_key)):
    await db.execute(update(User).where(User.id == user_id).values(plan=plan))
    return {"status": "updated", "plan": plan}

@router.put("/users/{user_id}/status")
async def toggle_status(user_id: str, is_active: bool, db: AsyncSession = Depends(get_db),
                        api_key: str = Depends(require_api_key)):
    await db.execute(update(User).where(User.id == user_id).values(is_active=is_active))
    return {"status": "updated", "is_active": is_active}

@router.delete("/users/{user_id}")
async def delete_user(user_id: str, db: AsyncSession = Depends(get_db),
                      api_key: str = Depends(require_api_key)):
    await db.execute(delete(User).where(User.id == user_id))
    return {"status": "deleted"}
PYEOF

# ── api/apps.py ──────────────────────────────────────────────
cat > $BASE/api/apps.py << 'PYEOF'
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import date
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.core.database import get_db
from app.core.security import require_api_key, get_redis, generate_api_key
from app.models.models import App

router = APIRouter(tags=["Apps"])

class AppCreate(BaseModel):
    name: str
    bundle_id: str
    play_store_url: Optional[str] = ""
    category: Optional[str] = ""

def app_to_dict(a: App) -> dict:
    return {"id": a.bundle_id, "name": a.name, "bundle_id": a.bundle_id,
            "api_key": a.api_key, "play_store_url": a.play_store_url,
            "category": a.category, "is_active": a.is_active,
            "created_at": str(a.created_at)}

@router.post("/apps")
async def register_app(body: AppCreate, db: AsyncSession = Depends(get_db),
                       api_key: str = Depends(require_api_key)):
    existing = await db.execute(select(App).where(App.bundle_id == body.bundle_id))
    if existing.scalar_one_or_none():
        raise HTTPException(400, f"App '{body.bundle_id}' already exists")

    app_api_key = generate_api_key()
    app = App(bundle_id=body.bundle_id, name=body.name,
              api_key=app_api_key, play_store_url=body.play_store_url or "",
              category=body.category or "")
    db.add(app)
    await db.flush()

    # Redis: apikey → bundle_id mapping (fast auth)
    r = get_redis()
    await r.set(f"apikey:{app_api_key}", body.bundle_id)

    print(f"[APP] ✅ Registered {body.bundle_id}")
    return app_to_dict(app)

@router.get("/apps")
async def list_apps(db: AsyncSession = Depends(get_db),
                    api_key: str = Depends(require_api_key)):
    result = await db.execute(select(App).order_by(App.created_at.desc()))
    apps   = result.scalars().all()
    today  = date.today().strftime("%Y%m%d")
    r      = get_redis()
    out    = []
    for a in apps:
        d = app_to_dict(a)
        d["stats_today"] = {
            "clicks":   int(await r.get(f"stats:clicks:{a.bundle_id}:{today}") or 0),
            "installs": int(await r.get(f"stats:installs:{a.bundle_id}:{today}") or 0),
            "events":   int(await r.get(f"stats:events:{a.bundle_id}:{today}") or 0),
        }
        out.append(d)
    return out

@router.get("/apps/{bundle_id}")
async def get_app(bundle_id: str, db: AsyncSession = Depends(get_db),
                  api_key: str = Depends(require_api_key)):
    result = await db.execute(select(App).where(App.bundle_id == bundle_id))
    app    = result.scalar_one_or_none()
    if not app:
        raise HTTPException(404, "App not found")
    d     = app_to_dict(app)
    today = date.today().strftime("%Y%m%d")
    r     = get_redis()
    d["stats_today"] = {
        "clicks":   int(await r.get(f"stats:clicks:{bundle_id}:{today}") or 0),
        "installs": int(await r.get(f"stats:installs:{bundle_id}:{today}") or 0),
        "events":   int(await r.get(f"stats:events:{bundle_id}:{today}") or 0),
        "fraud":    int(await r.get(f"stats:fraud:{bundle_id}:{today}") or 0),
    }
    return d

@router.delete("/apps/{bundle_id}")
async def delete_app(bundle_id: str, db: AsyncSession = Depends(get_db),
                     api_key: str = Depends(require_api_key)):
    result = await db.execute(select(App).where(App.bundle_id == bundle_id))
    app    = result.scalar_one_or_none()
    if app:
        r = get_redis()
        await r.delete(f"apikey:{app.api_key}")
        await db.execute(delete(App).where(App.bundle_id == bundle_id))
    return {"status": "deleted"}

class TestDevice(BaseModel):
    gaid: str
    note: Optional[str] = ""

@router.post("/apps/{bundle_id}/test-devices")
async def add_test_device(bundle_id: str, body: TestDevice,
                          api_key: str = Depends(require_api_key)):
    r = get_redis()
    await r.sadd(f"test_devices:{bundle_id}", body.gaid)
    await r.set(f"test_gaid:{body.gaid}", bundle_id)
    return {"status": "added", "gaid": body.gaid}

@router.get("/apps/{bundle_id}/test-devices")
async def list_test_devices(bundle_id: str, api_key: str = Depends(require_api_key)):
    r = get_redis()
    return {"bundle_id": bundle_id,
            "test_devices": list(await r.smembers(f"test_devices:{bundle_id}"))}

@router.delete("/apps/{bundle_id}/test-devices/{gaid}")
async def remove_test_device(bundle_id: str, gaid: str,
                             api_key: str = Depends(require_api_key)):
    r = get_redis()
    await r.srem(f"test_devices:{bundle_id}", gaid)
    await r.delete(f"test_gaid:{gaid}")
    return {"status": "removed", "gaid": gaid}
PYEOF

# ── api/campaigns.py ─────────────────────────────────────────
cat > $BASE/api/campaigns.py << 'PYEOF'
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, date
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update
from app.core.database import get_db
from app.core.security import require_api_key, get_redis
from app.models.models import Campaign, App
import uuid, json

router = APIRouter(tags=["Campaigns"])

REDIS_CAMP_TTL = 86400 * 7  # 7 days cache

class CampaignCreate(BaseModel):
    name: str
    app_id: str
    source: str = "pubscale"
    offer_id: Optional[str] = None
    play_store_url: str = ""
    postback_url: Optional[str] = None
    events: Dict[str, Any] = {}

def camp_to_dict(c: Campaign) -> dict:
    return {"id": c.id, "name": c.name, "app_id": c.app_id,
            "source": c.source, "offer_id": c.offer_id,
            "play_store_url": c.play_store_url,
            "postback_url": c.postback_url,
            "events": c.events or {}, "tracking_url": c.tracking_url,
            "is_active": c.is_active, "created_at": str(c.created_at)}

async def cache_campaign(r, camp_dict: dict):
    cid = camp_dict["id"]
    await r.setex(f"campaign:{cid}", REDIS_CAMP_TTL, json.dumps(camp_dict))
    if camp_dict.get("offer_id") and camp_dict.get("app_id"):
        await r.setex(
            f"campaign:offer:{camp_dict['offer_id']}:{camp_dict['app_id']}",
            REDIS_CAMP_TTL, json.dumps(camp_dict)
        )

@router.post("/campaigns")
async def create_campaign(body: CampaignCreate, db: AsyncSession = Depends(get_db),
                          api_key: str = Depends(require_api_key)):
    # Validate app
    app_result = await db.execute(select(App).where(App.bundle_id == body.app_id))
    if not app_result.scalar_one_or_none():
        raise HTTPException(404, f"App '{body.app_id}' not found")

    campaign_id = str(uuid.uuid4())
    tracking_url = (
        f"https://track.apptrack.in/v1/click"
        f"?clickid={{clickid}}&offer_id={{offer_id}}"
        f"&pid={{pid}}&geo={{geo}}&campaign_id={campaign_id}"
    )
    camp = Campaign(
        id=campaign_id, name=body.name, app_id=body.app_id,
        source=body.source, offer_id=body.offer_id,
        play_store_url=body.play_store_url, postback_url=body.postback_url,
        events=body.events, tracking_url=tracking_url,
    )
    db.add(camp)
    await db.flush()

    d = camp_to_dict(camp)
    r = get_redis()
    await cache_campaign(r, d)
    return d

@router.get("/campaigns")
async def list_campaigns(app_id: Optional[str] = Query(None),
                         db: AsyncSession = Depends(get_db),
                         api_key: str = Depends(require_api_key)):
    q = select(Campaign).order_by(Campaign.created_at.desc())
    if app_id:
        q = q.where(Campaign.app_id == app_id)
    result = await db.execute(q)
    camps  = result.scalars().all()
    today  = date.today().strftime("%Y%m%d")
    r      = get_redis()
    out    = []
    for c in camps:
        d = camp_to_dict(c)
        d["stats_today"] = {
            "clicks":   int(await r.get(f"stats:campaign:{c.id}:clicks:{today}") or 0),
            "installs": int(await r.get(f"stats:campaign:{c.id}:installs:{today}") or 0),
            "events":   int(await r.get(f"stats:campaign:{c.id}:events:{today}") or 0),
        }
        out.append(d)
    return out

@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db),
                       api_key: str = Depends(require_api_key)):
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    camp   = result.scalar_one_or_none()
    if not camp:
        raise HTTPException(404, "Campaign not found")
    d     = camp_to_dict(camp)
    today = date.today().strftime("%Y%m%d")
    r     = get_redis()
    d["stats_today"] = {
        "clicks":   int(await r.get(f"stats:campaign:{campaign_id}:clicks:{today}") or 0),
        "installs": int(await r.get(f"stats:campaign:{campaign_id}:installs:{today}") or 0),
        "events":   int(await r.get(f"stats:campaign:{campaign_id}:events:{today}") or 0),
    }
    return d

@router.patch("/campaigns/{campaign_id}")
async def update_campaign(campaign_id: str, body: dict,
                          db: AsyncSession = Depends(get_db),
                          api_key: str = Depends(require_api_key)):
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    camp   = result.scalar_one_or_none()
    if not camp:
        raise HTTPException(404, "Campaign not found")
    allowed = {"name", "postback_url", "events", "is_active", "play_store_url"}
    for k, v in body.items():
        if k in allowed:
            setattr(camp, k, v)
    await db.flush()
    d = camp_to_dict(camp)
    r = get_redis()
    await cache_campaign(r, d)
    return d

@router.delete("/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str, db: AsyncSession = Depends(get_db),
                          api_key: str = Depends(require_api_key)):
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    camp   = result.scalar_one_or_none()
    if camp:
        r = get_redis()
        await r.delete(f"campaign:{campaign_id}")
        if camp.offer_id:
            await r.delete(f"campaign:offer:{camp.offer_id}:{camp.app_id}")
        await db.execute(delete(Campaign).where(Campaign.id == campaign_id))
    return {"status": "deleted"}

# ── Internal helpers (used by events.py) ─────────────────────
async def get_campaign_cached(campaign_id: str, db: AsyncSession) -> Optional[dict]:
    """Redis first, fallback to DB"""
    r = get_redis()
    cached = await r.get(f"campaign:{campaign_id}")
    if cached:
        return json.loads(cached)
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    camp   = result.scalar_one_or_none()
    if camp:
        d = camp_to_dict(camp)
        await cache_campaign(r, d)
        return d
    return None
PYEOF

# ── api/events.py ────────────────────────────────────────────
cat > $BASE/api/events.py << 'PYEOF'
from fastapi import APIRouter, Request, Depends, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import json, httpx, time
from app.core.database import get_db
from app.core.security import require_api_key, get_redis
from app.models.models import Install, Event, FraudLog
from app.api.campaigns import get_campaign_cached

router = APIRouter(tags=["Events"])

CLICK_INSTALL_WINDOW   = 7 * 86400
POST_INSTALL_EVENT_WIN = 30 * 86400
MIN_CLICK_TO_INSTALL   = 30
MAX_INSTALLS_PER_IP    = 5

EMULATOR_MODELS    = ["sdk_gphone", "generic", "emulator", "android sdk built"]
SUSPICIOUS_SOURCES = ["com.android.shell", "adb"]

class InstallRequest(BaseModel):
    app_id: str
    uid: str
    device_id: str
    clickid: Optional[str] = None
    campaign_id: Optional[str] = None
    advertising_id: Optional[str] = None
    app_set_id: Optional[str] = None
    os_version: Optional[str] = None
    app_version: Optional[str] = None
    device_model: Optional[str] = None
    brand: Optional[str] = None
    cpu_abi: Optional[str] = None
    sensors: Optional[list] = None
    network: Optional[str] = None
    mcc: Optional[str] = None
    mnc: Optional[str] = None
    carrier: Optional[str] = None
    country: Optional[str] = None
    install_source: Optional[str] = None
    install_date: Optional[str] = None
    first_launch_date: Optional[str] = None
    last_boot_time: Optional[int] = None
    counter: Optional[int] = None
    referrer: Optional[str] = None
    build_id: Optional[str] = None
    screen: Optional[dict] = None
    ivc: Optional[bool] = None
    is_debug: Optional[bool] = False
    sig: Optional[str] = None

class EventRequest(BaseModel):
    app_id: str
    uid: str
    device_id: str
    event_name: str = Field(..., min_length=1, max_length=100)
    event_uuid: str
    clickid: Optional[str] = None
    campaign_id: Optional[str] = None
    advertising_id: Optional[str] = None
    event_value: Optional[float] = None
    data: Optional[Dict[str, Any]] = {}
    is_debug: Optional[bool] = False
    sig: Optional[str] = None

def now_ts() -> int:
    return int(time.time())

def parse_referrer(referrer: str) -> dict:
    result = {}
    if not referrer:
        return result
    try:
        from urllib.parse import unquote, parse_qs
        params = parse_qs(unquote(referrer))
        result["clickid"]     = params.get("at_click",    [None])[0]
        result["campaign_id"] = params.get("at_campaign", [None])[0]
    except Exception:
        pass
    return result

def check_conditions(event_name: str, data: dict, conditions: dict) -> bool:
    if not conditions:
        return True
    if "min_level" in conditions:
        return int(data.get("level", 0)) >= int(conditions["min_level"])
    if "min_score" in conditions:
        return int(data.get("score", 0)) >= int(conditions["min_score"])
    return True

async def detect_fraud(body: InstallRequest, ip: str, click_time: Optional[int], r) -> Optional[str]:
    if body.is_debug:
        return None
    null_gaid = "00000000-0000-0000-0000-000000000000"
    if body.advertising_id and body.advertising_id != null_gaid:
        if await r.get(f"test_gaid:{body.advertising_id}"):
            return None
    if body.cpu_abi and "x86" in body.cpu_abi.lower():
        return f"emulator_cpu:{body.cpu_abi}"
    if body.device_model:
        for em in EMULATOR_MODELS:
            if em in body.device_model.lower():
                return f"emulator_model:{body.device_model}"
    if body.sensors is not None and len(body.sensors) == 0:
        return "emulator_no_sensors"
    if body.install_source:
        for s in SUSPICIOUS_SOURCES:
            if s in body.install_source.lower():
                return f"suspicious_source:{body.install_source}"
    if click_time and (now_ts() - click_time) < MIN_CLICK_TO_INSTALL:
        return f"bot_too_fast:{now_ts()-click_time}s"
    ip_key = f"ip_installs:{body.app_id}:{ip}:{datetime.utcnow().strftime('%Y%m%d')}"
    if int(await r.get(ip_key) or 0) >= MAX_INSTALLS_PER_IP:
        return f"ip_limit:{ip}"
    if body.last_boot_time:
        boot_age = (now_ts() * 1000 - body.last_boot_time) / 1000
        if boot_age < 300:
            return f"fresh_boot:{boot_age:.0f}s"
    return None

async def fire_postback(url: str, clickid: str, extra: dict = {}):
    try:
        final_url = url.replace("{clickid}", clickid)
        for k, v in extra.items():
            final_url = final_url.replace(f"{{{k}}}", str(v))
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(final_url)
            print(f"[POSTBACK] ✅ {resp.status_code} → {final_url}")
    except Exception as e:
        print(f"[POSTBACK] ❌ {e}")

@router.post("/install")
async def track_install(
    req: Request, body: InstallRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    r   = get_redis()
    ip  = req.headers.get("CF-Connecting-IP", req.client.host if req.client else "")

    clickid     = body.clickid
    campaign_id = body.campaign_id
    if not clickid and body.referrer:
        parsed      = parse_referrer(body.referrer)
        clickid     = parsed.get("clickid")
        campaign_id = parsed.get("campaign_id")

    # Redis dedup (fast)
    null_gaid = "00000000-0000-0000-0000-000000000000"
    if await r.get(f"installed:device:{body.app_id}:{body.device_id}"):
        return {"status": "ok", "duplicate": True}
    if body.advertising_id and body.advertising_id != null_gaid:
        if await r.get(f"installed:gaid:{body.app_id}:{body.advertising_id}"):
            return {"status": "ok", "duplicate": True}

    # Click validation
    click_time = None
    if clickid:
        click_raw = await r.get(f"click:{clickid}")
        if click_raw:
            try:
                ct = datetime.fromisoformat(json.loads(click_raw).get("click_time", ""))
                click_time = int(ct.timestamp())
                if now_ts() - click_time > CLICK_INSTALL_WINDOW:
                    clickid = None; campaign_id = None
            except Exception:
                pass
        else:
            clickid = None

    # Fraud detection
    fraud_reason = await detect_fraud(body, ip, click_time, r)
    if fraud_reason:
        print(f"[FRAUD] 🚨 app={body.app_id} uid={body.uid} reason={fraud_reason}")
        # Save to DB + Redis
        fraud_log = FraudLog(app_id=body.app_id, device_id=body.device_id,
                             uid=body.uid, reason=fraud_reason, ip_address=ip)
        db.add(fraud_log)
        pipe = r.pipeline()
        pipe.setex(f"fraud:{body.app_id}:{body.device_id}", 86400 * 7, fraud_reason)
        today = datetime.utcnow().strftime("%Y%m%d")
        pipe.incr(f"stats:fraud:{body.app_id}:{today}")
        pipe.expire(f"stats:fraud:{body.app_id}:{today}", 86400 * 90)
        await pipe.execute()
        return {"status": "ok", "flagged": True}

    # Save install to PostgreSQL
    install = Install(
        app_id=body.app_id, uid=body.uid, device_id=body.device_id,
        advertising_id=body.advertising_id, clickid=clickid,
        campaign_id=campaign_id, country=body.country,
        device_model=body.device_model, os_version=body.os_version,
        app_version=body.app_version, network=body.network,
        carrier=body.carrier, brand=body.brand,
        ip_address=ip, is_debug=body.is_debug, ivc=body.ivc,
    )
    db.add(install)

    # Redis: dedup + attribution + counters (pipeline)
    ts    = now_ts()
    today = datetime.utcnow().strftime("%Y%m%d")
    pipe  = r.pipeline()
    pipe.setex(f"installed:device:{body.app_id}:{body.device_id}", 86400 * 365, "1")
    if body.advertising_id and body.advertising_id != null_gaid:
        pipe.setex(f"installed:gaid:{body.app_id}:{body.advertising_id}", 86400 * 365, "1")
    ip_key = f"ip_installs:{body.app_id}:{ip}:{today}"
    pipe.incr(ip_key); pipe.expire(ip_key, 86400)
    pipe.setex(f"install_time:{body.app_id}:{body.uid}", 86400 * 60, str(ts))
    if clickid:
        pipe.setex(f"uid_click:{body.app_id}:{body.uid}",         86400 * 30, clickid)
        pipe.setex(f"uid_campaign:{body.app_id}:{body.uid}",       86400 * 30, campaign_id or "")
        pipe.setex(f"device_click:{body.app_id}:{body.device_id}", 86400 * 30, clickid)
    pipe.incr(f"stats:installs:{body.app_id}:{today}")
    pipe.expire(f"stats:installs:{body.app_id}:{today}", 86400 * 90)
    if campaign_id:
        pipe.incr(f"stats:campaign:{campaign_id}:installs:{today}")
        pipe.expire(f"stats:campaign:{campaign_id}:installs:{today}", 86400 * 90)
    await pipe.execute()

    print(f"[INSTALL] ✅ app={body.app_id} uid={body.uid} clickid={clickid}")

    # Postback
    if clickid and campaign_id:
        camp = await get_campaign_cached(campaign_id, db)
        if camp:
            cfg = camp.get("events", {}).get("install")
            if cfg and cfg.get("postback_url"):
                background_tasks.add_task(fire_postback, cfg["postback_url"], clickid)
            elif camp.get("postback_url"):
                background_tasks.add_task(fire_postback, camp["postback_url"], clickid,
                    {"event": "install", "app_id": body.app_id})

    return {"status": "ok", "server_time": datetime.utcnow().isoformat()}

@router.post("/event")
async def track_event(
    req: Request, body: EventRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    r = get_redis()

    # Dedup
    if await r.get(f"event:{body.event_uuid}"):
        return {"status": "ok", "duplicate": True}
    await r.setex(f"event:{body.event_uuid}", 86400 * 7, "1")

    # Fraud check
    if not body.is_debug and await r.get(f"fraud:{body.app_id}:{body.device_id}"):
        return {"status": "ok", "flagged": True}

    # Post-install window
    install_ts = await r.get(f"install_time:{body.app_id}:{body.uid}")
    if install_ts and (now_ts() - int(install_ts)) > POST_INSTALL_EVENT_WIN:
        return {"status": "ok", "expired": True}

    # Attribution
    clickid = (body.clickid
               or await r.get(f"uid_click:{body.app_id}:{body.uid}")
               or await r.get(f"device_click:{body.app_id}:{body.device_id}"))
    campaign_id = (body.campaign_id or await r.get(f"uid_campaign:{body.app_id}:{body.uid}"))

    # Save to PostgreSQL
    event = Event(
        app_id=body.app_id, uid=body.uid, device_id=body.device_id,
        event_name=body.event_name, event_uuid=body.event_uuid,
        event_value=body.event_value, data=body.data or {},
        clickid=clickid, campaign_id=campaign_id, is_debug=body.is_debug,
    )
    db.add(event)

    # Redis counters
    today = datetime.utcnow().strftime("%Y%m%d")
    pipe  = r.pipeline()
    pipe.incr(f"stats:events:{body.app_id}:{today}")
    pipe.expire(f"stats:events:{body.app_id}:{today}", 86400 * 90)
    pipe.incr(f"stats:events:{body.app_id}:{body.event_name}:{today}")
    pipe.expire(f"stats:events:{body.app_id}:{body.event_name}:{today}", 86400 * 90)
    if campaign_id:
        pipe.incr(f"stats:campaign:{campaign_id}:events:{today}")
        pipe.expire(f"stats:campaign:{campaign_id}:events:{today}", 86400 * 90)
    await pipe.execute()

    print(f"[EVENT] {body.event_name} app={body.app_id} uid={body.uid} clickid={clickid}")

    # Postback
    if clickid and campaign_id:
        camp = await get_campaign_cached(campaign_id, db)
        if camp:
            cfg = camp.get("events", {}).get(body.event_name)
            if cfg and cfg.get("postback_url") and check_conditions(
                body.event_name, body.data or {}, cfg.get("conditions", {})
            ):
                background_tasks.add_task(fire_postback, cfg["postback_url"], clickid, body.data or {})
            elif camp.get("postback_url"):
                background_tasks.add_task(fire_postback, camp["postback_url"], clickid,
                    {"event": body.event_name, "value": str(body.event_value or ""),
                     "app_id": body.app_id})

    return {"status": "ok", "event_uuid": body.event_uuid, "server_time": datetime.utcnow().isoformat()}
PYEOF

# ── api/dashboard_routes.py ──────────────────────────────────
cat > $BASE/api/dashboard_routes.py << 'PYEOF'
from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.core.database import get_db
from app.core.security import require_api_key, get_redis
from app.models.models import Install, Event, FraudLog, App, Campaign
from datetime import datetime, timedelta, date
from typing import Optional
import json

router = APIRouter(tags=["Dashboard"])

@router.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    with open("/opt/attribution/dashboard.html") as f:
        return f.read()

@router.get("/v1/stats")
async def get_stats(
    app_id: Optional[str] = Query(None),
    campaign_id: Optional[str] = Query(None),
    days: int = Query(7, ge=1, le=90),
    api_key: str = Depends(require_api_key),
):
    r     = get_redis()
    today = datetime.utcnow()
    daily = []
    totals = {"clicks": 0, "installs": 0, "events": 0, "fraud": 0}

    for i in range(days):
        d = (today - timedelta(days=i)).strftime("%Y%m%d")
        if campaign_id:
            row = {
                "date":     d,
                "clicks":   int(await r.get(f"stats:campaign:{campaign_id}:clicks:{d}") or 0),
                "installs": int(await r.get(f"stats:campaign:{campaign_id}:installs:{d}") or 0),
                "events":   int(await r.get(f"stats:campaign:{campaign_id}:events:{d}") or 0),
                "fraud":    0,
            }
        elif app_id:
            row = {
                "date":     d,
                "clicks":   int(await r.get(f"stats:clicks:{app_id}:{d}") or 0),
                "installs": int(await r.get(f"stats:installs:{app_id}:{d}") or 0),
                "events":   int(await r.get(f"stats:events:{app_id}:{d}") or 0),
                "fraud":    int(await r.get(f"stats:fraud:{app_id}:{d}") or 0),
            }
        else:
            # Master — sum all apps from DB app_list
            app_ids = list(await r.smembers("app_list"))
            row = {"date": d, "clicks": 0, "installs": 0, "events": 0, "fraud": 0}
            for aid in app_ids:
                row["clicks"]   += int(await r.get(f"stats:clicks:{aid}:{d}") or 0)
                row["installs"] += int(await r.get(f"stats:installs:{aid}:{d}") or 0)
                row["events"]   += int(await r.get(f"stats:events:{aid}:{d}") or 0)
                row["fraud"]    += int(await r.get(f"stats:fraud:{aid}:{d}") or 0)
        daily.append(row)
        for k in ("clicks", "installs", "events", "fraud"):
            totals[k] += row[k]

    totals["cvr"] = round(totals["installs"] / totals["clicks"] * 100, 2) if totals["clicks"] > 0 else 0
    return {"daily": daily, "totals": totals, "days": days,
            "app_id": app_id, "campaign_id": campaign_id}

@router.get("/v1/installs")
async def get_installs(
    app_id: Optional[str] = Query(None),
    campaign_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    q = select(Install).order_by(Install.server_time.desc()).limit(limit).offset(offset)
    if app_id:
        q = q.where(Install.app_id == app_id)
    if campaign_id:
        q = q.where(Install.campaign_id == campaign_id)
    result   = await db.execute(q)
    installs = result.scalars().all()
    return {"installs": [
        {"id": i.id, "app_id": i.app_id, "uid": i.uid, "device_id": i.device_id,
         "clickid": i.clickid, "campaign_id": i.campaign_id, "country": i.country,
         "device_model": i.device_model, "os_version": i.os_version,
         "app_version": i.app_version, "network": i.network,
         "ip_address": i.ip_address, "is_debug": i.is_debug,
         "server_time": str(i.server_time)} for i in installs
    ], "count": len(installs), "offset": offset}

@router.get("/v1/events/log")
async def get_events_log(
    app_id: Optional[str] = Query(None),
    event_name: Optional[str] = Query(None),
    campaign_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    q = select(Event).order_by(Event.server_time.desc()).limit(limit).offset(offset)
    if app_id:
        q = q.where(Event.app_id == app_id)
    if event_name:
        q = q.where(Event.event_name == event_name)
    if campaign_id:
        q = q.where(Event.campaign_id == campaign_id)
    result = await db.execute(q)
    events = result.scalars().all()
    return {"events": [
        {"id": e.id, "app_id": e.app_id, "uid": e.uid,
         "event_name": e.event_name, "event_uuid": e.event_uuid,
         "event_value": e.event_value, "data": e.data,
         "clickid": e.clickid, "campaign_id": e.campaign_id,
         "is_debug": e.is_debug, "server_time": str(e.server_time)} for e in events
    ], "count": len(events), "offset": offset}

@router.get("/v1/fraud")
async def get_fraud(
    app_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    q = select(FraudLog).order_by(FraudLog.server_time.desc()).limit(limit).offset(offset)
    if app_id:
        q = q.where(FraudLog.app_id == app_id)
    result = await db.execute(q)
    logs   = result.scalars().all()
    return {"blocked": [
        {"id": f.id, "app_id": f.app_id, "device_id": f.device_id,
         "uid": f.uid, "reason": f.reason, "ip_address": f.ip_address,
         "server_time": str(f.server_time)} for f in logs
    ], "count": len(logs)}

@router.get("/v1/sdk-logs")
async def get_sdk_logs(api_key: str = Depends(require_api_key)):
    r = get_redis()
    return {"logs": await r.lrange("sdk_logs", 0, 199)}

@router.get("/v1/web-logs")
async def get_web_logs(api_key: str = Depends(require_api_key)):
    r = get_redis()
    return {"logs": await r.lrange("web_logs", 0, 199)}
PYEOF

# ── Warm Redis app_list from DB on startup ────────────────────
cat > $BASE/core/startup.py << 'PYEOF'
"""
On startup: warm Redis app_list + apikey mappings from PostgreSQL
So Redis is never the single source of truth for auth
"""
from app.core.database import AsyncSessionLocal
from app.core.security import get_redis
from app.models.models import App, Campaign
from sqlalchemy import select
import json

async def warm_redis_cache():
    r = get_redis()
    async with AsyncSessionLocal() as db:
        # Warm app apikeys
        apps = (await db.execute(select(App))).scalars().all()
        for app in apps:
            await r.set(f"apikey:{app.api_key}", app.bundle_id)
            await r.sadd("app_list", app.bundle_id)
        print(f"[STARTUP] ✅ Warmed {len(apps)} apps into Redis")

        # Warm active campaign cache
        camps = (await db.execute(select(Campaign).where(Campaign.is_active == True))).scalars().all()
        for c in camps:
            d = {"id": c.id, "name": c.name, "app_id": c.app_id,
                 "source": c.source, "offer_id": c.offer_id,
                 "postback_url": c.postback_url, "events": c.events or {},
                 "tracking_url": c.tracking_url, "is_active": c.is_active}
            await r.setex(f"campaign:{c.id}", 86400 * 7, json.dumps(d))
            if c.offer_id:
                await r.setex(f"campaign:offer:{c.offer_id}:{c.app_id}", 86400 * 7, json.dumps(d))
        print(f"[STARTUP] ✅ Warmed {len(camps)} campaigns into Redis")
PYEOF

# ── main.py ──────────────────────────────────────────────────
cat > $BASE/main.py << 'PYEOF'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.core.database import init_db
from app.core.config import settings
from app.core.middleware import log_middleware
from app.core.startup import warm_redis_cache
from app.api import events, postback, health, apps, clicks, campaigns, dashboard_routes, auth

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await warm_redis_cache()
    yield

app = FastAPI(
    title="AppTrack MMP API",
    version="3.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)

app.middleware("http")(log_middleware)

app.include_router(health.router,             prefix="/v1")
app.include_router(auth.router,               prefix="/v1")
app.include_router(clicks.router,             prefix="/v1")
app.include_router(events.router,             prefix="/v1")
app.include_router(postback.router,           prefix="/v1")
app.include_router(apps.router,               prefix="/v1")
app.include_router(campaigns.router,          prefix="/v1")
app.include_router(dashboard_routes.router)
PYEOF

# ── Restart ───────────────────────────────────────────────────
echo ""
echo "🔄 Restarting backend..."
cd /opt/attribution/docker 2>/dev/null || cd /opt/attribution 2>/dev/null || true
docker compose restart backend 2>/dev/null || \
docker-compose restart backend 2>/dev/null || \
docker restart attribution_backend 2>/dev/null || true

sleep 3
echo ""
echo "📋 Backend logs (last 20 lines):"
docker logs attribution_backend --tail=20 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅  PostgreSQL persistent storage — DONE!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "📦 DATA STORAGE:"
echo "   PostgreSQL → users, apps, campaigns, installs, events, fraud"
echo "   Redis      → auth cache, dedup, rate limit, click data, stats"
echo ""
echo "🔁 REDIS RESTART SAFE:"
echo "   Startup mein PostgreSQL se Redis auto-warm hoga"
echo "   apikey:{key} → bundle_id  (app auth)"
echo "   campaign:{id} → data      (fast lookup)"
echo ""
echo "📊 DASHBOARD ENDPOINTS:"
echo "   GET /v1/installs?app_id=X&limit=50&offset=0"
echo "   GET /v1/events/log?app_id=X&event_name=level_complete"
echo "   GET /v1/fraud?app_id=X"
echo "   GET /v1/stats?app_id=X&days=30"
echo "   GET /v1/stats?campaign_id=UUID&days=7"
echo "════════════════════════════════════════════════════════════"
