from __future__ import annotations

from datetime import datetime, date, time, timedelta, timezone
from typing import Optional, Dict, List, Tuple, Any
import secrets
import re

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import SQLModel, Field, create_engine, Session, select
from sqlalchemy import delete, func
from passlib.context import CryptContext
from itsdangerous import URLSafeSerializer
from jinja2 import Environment, FileSystemLoader, select_autoescape

# ---- Timezone (Windows에서도 안정적으로 동작하도록 KST 고정) ----
APP_TZ = timezone(timedelta(hours=9))  # KST +09:00

DB_URL = os.getenv("DB_URL", "sqlite:///./mentoring.db")  # 기본은 로컬
SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"  # 배포 시 반드시 변경
COOKIE_NAME = "mentoring_session"

# bcrypt 대신 pbkdf2_sha256 사용 (길이 제한/호환 문제 회피)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
serializer = URLSafeSerializer(SECRET, salt="session")

app = FastAPI()


# API 호출(특히 fetch)에서 500이 text/plain으로 내려오면 프론트에서 res.json()이 깨질 수 있음.
# /api/* 경로에 한해 내부 오류도 JSON으로 돌려서 원인 파악/알림이 가능하게 함.
@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/"):
        # 상세 예외 메시지는 노출하지 않음(보안/안정성)
        return JSONResponse(status_code=500, content={"ok": False, "detail": "Internal Server Error"})
    # 화면 페이지는 기본 텍스트 오류로 처리
    return PlainTextResponse("Internal Server Error", status_code=500)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"])
)

engine = create_engine(DB_URL, echo=False)


# -------------------------
# DB Models
# -------------------------
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    role: str  # "prof" or "student"
    username: str = Field(index=True, unique=True)
    password_hash: str
    display_name: str


class Term(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    is_active: bool = True


class ConsultationRound(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    term_id: int = Field(foreign_key="term.id")
    name: str
    duration_min: int
    capacity: int
    max_per_student: int


class Slot(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    round_id: int = Field(foreign_key="consultationround.id")
    starts_at: datetime
    ends_at: datetime
    is_open: bool = True


class Booking(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    slot_id: int = Field(foreign_key="slot.id", index=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=APP_TZ))


class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str


def migrate_sqlite_schema(engine):
    """Very small SQLite migration helper.

    Local/Render deployments often keep the same SQLite file while code evolves.
    If a table is missing a newly-added column, SQLite can raise OperationalError
    on INSERT/UPDATE. This helper adds a few expected columns when missing.
    """
    # Only for SQLite
    try:
        url = str(engine.url)
    except Exception:
        return
    if not url.startswith("sqlite"):
        return

    # table -> {column: sql_type}
    required_cols = {
        "booking": {
            "created_at": "DATETIME",
        },
        "slot": {
            "is_open": "BOOLEAN",
        },
    }

    from sqlalchemy import text

    with engine.begin() as conn:
        for table, cols in required_cols.items():
            try:
                info = conn.execute(text(f"PRAGMA table_info({table});")).fetchall()
            except Exception:
                continue
            existing = {row[1] for row in info}
            for col, coltype in cols.items():
                if col in existing:
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {coltype};"))
                except Exception:
                    pass


def create_db():
    """Create tables and run lightweight SQLite migrations."""
    SQLModel.metadata.create_all(engine)
    migrate_sqlite_schema(engine)

# -------------------------
# Helpers
# -------------------------
def render(request: Request, name: str, **ctx):
    tpl = templates.get_template(name)
    return HTMLResponse(tpl.render(request=request, **ctx))


def get_db():
    with Session(engine) as session:
        yield session


def hash_pw(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_pw(pw: str, hashed: str) -> bool:
    return pwd_context.verify(pw, hashed)


def set_session(resp: RedirectResponse, user_id: int):
    token = serializer.dumps({"user_id": user_id})
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", secure=False)


def clear_session(resp: RedirectResponse):
    resp.delete_cookie(COOKIE_NAME)


def get_current_user(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        data = serializer.loads(token)
        user_id = int(data["user_id"])
    except Exception:
        return None
    return db.get(User, user_id)


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    u = get_current_user(request, db)
    if not u:
        raise HTTPException(status_code=401, detail="로그인 필요")
    return u


def require_prof(user: User = Depends(require_user)) -> User:
    if user.role != "prof":
        raise HTTPException(status_code=403, detail="교수 권한 필요")
    return user


def now_kst() -> datetime:
    return datetime.now(tz=APP_TZ)


def cutoff_ok(starts_at: datetime) -> bool:
    """
    당일에는 변경/취소/예약 불가.
    기준: 슬롯 시작일의 '00:00'(KST) 이전까지만 허용.
    """
    now = now_kst()
    slot_date = as_kst(starts_at).date()
    slot_day_start = datetime.combine(slot_date, time(0, 0), tzinfo=APP_TZ)
    return now < slot_day_start


def get_setting(db: Session, key: str, default: str = "") -> str:
    s = db.get(Setting, key)
    return s.value if s else default


def set_setting(db: Session, key: str, value: str):
    s = db.get(Setting, key)
    if not s:
        s = Setting(key=key, value=value)
    else:
        s.value = value
    db.add(s)
    db.commit()


def slot_current_count(db: Session, slot_id: int) -> int:
    return len(db.exec(select(Booking).where(Booking.slot_id == slot_id)).all())


def count_my_round_bookings(db: Session, user_id: int, round_id: int) -> int:
    # SQLModel returns a list of scalar ints for `select(Slot.id)`.
    # (Some ORMs return one-item tuples; normalize to a plain int list.)
    slot_ids = list(db.exec(select(Slot.id).where(Slot.round_id == round_id)).all())
    if not slot_ids:
        return 0
    my = db.exec(select(Booking).where(Booking.user_id == user_id)).all()
    slot_set = set(slot_ids)
    return sum(1 for b in my if b.slot_id in slot_set)


def as_kst(dt: datetime) -> datetime:
    """SQLite 저장/로드 과정에서 tzinfo가 누락되는 경우가 있어 KST로 보정함.

    - tzinfo 없음: 이미 한국시간으로 입력된 값이라고 가정하고 KST를 부여함
    - tzinfo 있음: KST로 변환해 반환
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=APP_TZ)
    return dt.astimezone(APP_TZ)


def iso_dt(dt: datetime) -> str:
    # FullCalendar가 이해하는 ISO8601 형식(타임존 포함)
    # tzinfo가 없는 datetime을 서버 로컬(UTC)로 오해하면 요일/날짜가 밀리는 문제가 생김
    return as_kst(dt).isoformat()


# -------------------------
# Seed
# -------------------------
def ensure_initial_data(db: Session):
    prof = db.exec(select(User).where(User.role == "prof")).first()
    if not prof:
        u = User(role="prof", username="prof", password_hash=hash_pw("prof1234"), display_name="교수")
        db.add(u)

    term = db.exec(select(Term).where(Term.is_active == True)).first()
    if not term:
        db.add(Term(name="기본 텀", is_active=True))

    if not db.get(Setting, "invite_code"):
        db.add(Setting(key="invite_code", value="MENTORING2026"))

    db.commit()


@app.on_event("startup")
def on_startup():
    create_db()
    with Session(engine) as db:
        ensure_initial_data(db)


# -------------------------
# Auth / Home
# -------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return render(request, "home.html", user=user)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "login.html", error=None)


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.exec(select(User).where(User.username == username)).first()
    if not user or not verify_pw(password, user.password_hash):
        return render(Request, "login.html", error="아이디 또는 비밀번호 오류")  # type: ignore
    resp = RedirectResponse("/dashboard", status_code=303)
    set_session(resp, user.id)
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/", status_code=303)
    clear_session(resp)
    return resp


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    return render(request, "register.html", error=None, invite_code_hint="교수자가 안내한 초대코드 입력")


@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(...),
    invite_code: str = Form(...),
    db: Session = Depends(get_db)
):
    expected = get_setting(db, "invite_code", "")
    if not expected or invite_code.strip() != expected.strip():
        return render(request, "register.html", error="초대코드가 올바르지 않음", invite_code_hint="교수자가 안내한 초대코드 입력")

    if db.exec(select(User).where(User.username == username)).first():
        return render(request, "register.html", error="이미 존재하는 아이디", invite_code_hint="교수자가 안내한 초대코드 입력")

    u = User(role="student", username=username, password_hash=hash_pw(password), display_name=display_name)
    db.add(u)
    db.commit()
    resp = RedirectResponse("/dashboard", status_code=303)
    set_session(resp, u.id)
    return resp


@app.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    return RedirectResponse("/prof" if user.role == "prof" else "/student", status_code=303)


# -------------------------
# Professor pages
# -------------------------
@app.get("/prof", response_class=HTMLResponse)
def prof_panel(request: Request, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    term = db.exec(select(Term).where(Term.is_active == True)).first()
    rounds = db.exec(select(ConsultationRound).where(ConsultationRound.term_id == term.id)).all() if term else []
    students = db.exec(select(User).where(User.role == "student").order_by(User.username)).all()
    invite_code = get_setting(db, "invite_code", "MENTORING2026")
    err = request.query_params.get("err")
    return render(request, "prof.html", user=prof, term=term, rounds=rounds, students=students, invite_code=invite_code, err=err)


@app.post("/prof/round/{round_id}/delete")
def prof_delete_round(round_id: int, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    """차수(ROUND) 자체 삭제: 슬롯+예약까지 함께 삭제"""
    rnd = db.get(ConsultationRound, round_id)
    if not rnd:
        raise HTTPException(404, "차수 없음")

    # slots -> bookings 순서로 삭제
    slot_ids = [s.id for s in db.exec(select(Slot).where(Slot.round_id == round_id)).all()]
    if slot_ids:
        db.exec(delete(Booking).where(Booking.slot_id.in_(slot_ids)))
        db.exec(delete(Slot).where(Slot.id.in_(slot_ids)))
    db.exec(delete(ConsultationRound).where(ConsultationRound.id == round_id))
    db.commit()
    return RedirectResponse("/prof", status_code=303)


@app.post("/api/prof/students/{student_key}/reset_password")
def prof_reset_student_password(student_key: str, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    """학생 비밀번호는 조회할 수 없고, 교수자가 임시 비밀번호로 '초기화'만 가능함.

    student_key는 내부 id("1") 또는 username("s1") 둘 다 허용함.
    (화면 표시값/DB키 불일치로 버튼이 "아무 변화 없음"처럼 보이는 문제 방지 목적)
    """
    stu: Optional[User] = None
    if student_key.isdigit():
        stu = db.get(User, int(student_key))
        if stu and stu.role != "student":
            stu = None
    if not stu:
        stu = db.exec(select(User).where(User.username == student_key, User.role == "student")).first()

    if not stu:
        raise HTTPException(404, "학생 없음")

    temp_pw = secrets.token_urlsafe(6)[:10]  # 10자 내외
    # NOTE: project uses hash_pw()/verify_pw() helpers.
    # A previous refactor mistakenly called hash_password(), causing 500 errors.
    stu.password_hash = hash_pw(temp_pw)
    db.add(stu)
    db.commit()
    return {"ok": True, "student_id": stu.id, "username": stu.username, "temp_password": temp_pw}


@app.post("/api/prof/students/{student_key}/delete")
def prof_delete_student(student_key: str, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    """교수자 전용: 학생 계정 삭제(해당 학생 예약도 함께 삭제)."""
    stu: Optional[User] = None
    if student_key.isdigit():
        stu = db.get(User, int(student_key))
        if stu and stu.role != "student":
            stu = None
    if not stu:
        stu = db.exec(select(User).where(User.username == student_key, User.role == "student")).first()

    if not stu:
        raise HTTPException(404, "학생 없음")

    # 학생이 예약한 booking 먼저 삭제
    db.exec(delete(Booking).where(Booking.user_id == stu.id))
    db.delete(stu)
    db.commit()
    return {"ok": True, "deleted": True, "username": stu.username}


@app.post("/prof/term")
def prof_create_term(name: str = Form(...), db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    for t in db.exec(select(Term)).all():
        t.is_active = False
        db.add(t)
    db.add(Term(name=name, is_active=True))
    db.commit()
    return RedirectResponse("/prof", status_code=303)


@app.post("/prof/round")
def prof_create_round(
    name: str = Form(...),
    duration_min: int = Form(...),
    capacity: int = Form(...),
    max_per_student: int = Form(...),
    db: Session = Depends(get_db),
    prof: User = Depends(require_prof)
):
    term = db.exec(select(Term).where(Term.is_active == True)).first()
    if not term:
        raise HTTPException(400, "활성 Term 없음")

    clean_name = name.strip()
    if not clean_name:
        return RedirectResponse("/prof?err=차수%20이름을%20입력해야%20함", status_code=303)

    # 차수 이름 중복 방지(대소문자/앞뒤공백 무시)
    existing = db.exec(
        select(ConsultationRound).where(
            ConsultationRound.term_id == term.id,
            func.lower(ConsultationRound.name) == func.lower(clean_name),
        )
    ).first()
    if existing:
        return RedirectResponse(f"/prof?err=차수%20이름%20중복:%20{clean_name}", status_code=303)

    r = ConsultationRound(term_id=term.id, name=clean_name, duration_min=duration_min, capacity=capacity, max_per_student=max_per_student)
    db.add(r)
    db.commit()
    return RedirectResponse("/prof", status_code=303)


@app.post("/prof/invite_code")
def prof_set_invite_code(invite_code: str = Form(...), db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    set_setting(db, "invite_code", invite_code.strip())
    return RedirectResponse("/prof", status_code=303)


@app.post("/prof/change_password")
def prof_change_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
    db: Session = Depends(get_db),
    prof: User = Depends(require_prof)
):
    if not verify_pw(current_password, prof.password_hash):
        raise HTTPException(400, "현재 비밀번호 오류")
    if new_password != new_password_confirm:
        raise HTTPException(400, "새 비밀번호 확인 불일치")
    prof.password_hash = hash_pw(new_password)
    db.add(prof)
    db.commit()
    return RedirectResponse("/prof", status_code=303)


@app.get("/prof/round/{round_id}", response_class=HTMLResponse)
def prof_round_detail(round_id: int, request: Request, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    rnd = db.get(ConsultationRound, round_id)
    if not rnd:
        raise HTTPException(404, "Round 없음")
    return render(request, "prof_round_calendar.html", user=prof, rnd=rnd)


@app.post("/prof/round/{round_id}/generate_slots")
def prof_generate_slots(
    round_id: int,
    start_date: str = Form(...),
    end_date: str = Form(...),
    weekdays: str = Form(...),
    start_time: str = Form(...),
    end_time: str = Form(...),
    db: Session = Depends(get_db),
    prof: User = Depends(require_prof)
):
    rnd = db.get(ConsultationRound, round_id)
    if not rnd:
        raise HTTPException(404, "Round 없음")

    sd = date.fromisoformat(start_date)
    ed = date.fromisoformat(end_date)
    # 요일 파싱
    # 입력 예: "0,2,4" / "0.2.4" / "0 2 4" / "0/2/4"
    # 규칙: 월=0, 화=1, 수=2, 목=3, 금=4, 토=5, 일=6 (Python date.weekday 기준)
    tokens = re.findall(r"\d+", (weekdays or ""))
    wds = {int(t) for t in tokens if t.isdigit()}
    wds = {x for x in wds if 0 <= x <= 6}
    if not wds:
        raise HTTPException(status_code=400, detail="요일 입력 오류: 0~6 숫자를 입력해 주세요. 예) 0,2,4")
    st = time.fromisoformat(start_time)
    et = time.fromisoformat(end_time)

    cur = sd
    dur = timedelta(minutes=rnd.duration_min)
    while cur <= ed:
        if cur.weekday() in wds:
            day_start = datetime.combine(cur, st, tzinfo=APP_TZ)
            day_end = datetime.combine(cur, et, tzinfo=APP_TZ)
            slot_start = day_start
            while slot_start + dur <= day_end:
                slot_end = slot_start + dur
                db.add(Slot(round_id=round_id, starts_at=slot_start, ends_at=slot_end, is_open=True))
                slot_start = slot_end
        cur += timedelta(days=1)

    db.commit()
    return RedirectResponse(f"/prof/round/{round_id}", status_code=303)


@app.post("/prof/slot/{slot_id}/toggle")
def prof_toggle_slot(slot_id: int, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    s = db.get(Slot, slot_id)
    if not s:
        raise HTTPException(404, "Slot 없음")
    s.is_open = not s.is_open
    db.add(s)
    db.commit()
    return JSONResponse({"ok": True, "is_open": s.is_open})


# ---- Professor API: FullCalendar events ----
@app.get("/api/prof/round/{round_id}/events")
def prof_events(round_id: int, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    rnd = db.get(ConsultationRound, round_id)
    if not rnd:
        raise HTTPException(404, "Round 없음")

    slots = db.exec(select(Slot).where(Slot.round_id == round_id)).all()
    users = {u.id: u for u in db.exec(select(User)).all()}

    # bookings by slot
    bks = db.exec(select(Booking)).all()
    by_slot: Dict[int, List[User]] = {}
    for b in bks:
        if b.slot_id in [s.id for s in slots]:
            by_slot.setdefault(b.slot_id, []).append(users.get(b.user_id))

    events: List[Dict[str, Any]] = []
    for s in slots:
        us = by_slot.get(s.id, [])
        cnt = len(us)
        ss = as_kst(s.starts_at)
        ee = as_kst(s.ends_at)
        title = f"{ss.strftime('%H:%M')}-{ee.strftime('%H:%M')} | "
        title += ("CLOSED" if not s.is_open else f"{cnt}/{rnd.capacity}")
        if cnt > 0:
            title += " | " + ", ".join([u.display_name for u in us if u])

        # Color rules (prof view):
        # - 0/cap: keep default blue
        # - partial (e.g., 1/2): purple
        # - full (e.g., 2/2) or CLOSED: dark gray
        bg = None
        border = None
        text = None
        if (not s.is_open) or (cnt >= rnd.capacity and rnd.capacity > 0):
            bg = "#374151"       # 진회색
            border = "#374151"
            text = "#ffffff"
        elif cnt > 0:
            bg = "#7c3aed"       # 보라색
            border = "#7c3aed"
            text = "#ffffff"
        events.append({
            "id": str(s.id),
            "title": title,
            "start": iso_dt(s.starts_at),
            "end": iso_dt(s.ends_at),
            # month view에서 eventDisplay가 'list-item'인 경우 backgroundColor가 잘 안 먹어서 color도 같이 내려줌
            **({"backgroundColor": bg, "borderColor": border, "textColor": text, "color": bg} if bg else {}),
            "extendedProps": {
                "slotId": s.id,
                "isOpen": s.is_open,
                "count": cnt,
                "capacity": rnd.capacity,
            }
        })
    return JSONResponse(events)


# -------------------------
# Student pages
# -------------------------
@app.get("/student", response_class=HTMLResponse)
def student_panel(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if user.role != "student":
        return RedirectResponse("/prof", status_code=303)
    term = db.exec(select(Term).where(Term.is_active == True)).first()
    rounds = db.exec(select(ConsultationRound).where(ConsultationRound.term_id == term.id)).all() if term else []

    # 내 예약 목록
    my_bookings = db.exec(select(Booking).where(Booking.user_id == user.id)).all()
    slots = {s.id: s for s in db.exec(select(Slot)).all()}
    rnds = {r.id: r for r in rounds}
    my_items = []
    for b in my_bookings:
        s = slots.get(b.slot_id)
        if not s:
            continue
        r = rnds.get(s.round_id)
        if not r:
            continue
        my_items.append((b, s, r))
    my_items.sort(key=lambda x: x[1].starts_at)

    return render(request, "student.html", user=user, rounds=rounds, my_items=my_items)


@app.get("/student/round/{round_id}", response_class=HTMLResponse)
def student_round_calendar(round_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if user.role != "student":
        raise HTTPException(403, "학생만")
    rnd = db.get(ConsultationRound, round_id)
    if not rnd:
        raise HTTPException(404, "Round 없음")
    return render(request, "student_round_calendar.html", user=user, rnd=rnd)


# ---- Student API: FullCalendar events ----
@app.get("/api/student/round/{round_id}/events")
def student_events(round_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if user.role != "student":
        raise HTTPException(403, "학생만")
    rnd = db.get(ConsultationRound, round_id)
    if not rnd:
        raise HTTPException(404, "Round 없음")

    slots = db.exec(select(Slot).where(Slot.round_id == round_id)).all()
    users = {u.id: u for u in db.exec(select(User)).all()}
    bks = db.exec(select(Booking)).all()

    by_slot: Dict[int, List[User]] = {}
    for b in bks:
        by_slot.setdefault(b.slot_id, []).append(users.get(b.user_id))

    my_slot_ids = set([b.slot_id for b in db.exec(select(Booking).where(Booking.user_id == user.id)).all()])

    events: List[Dict[str, Any]] = []
    for s in slots:
        us = by_slot.get(s.id, [])
        count = len(us)
        full = (count >= rnd.capacity)
        closed = (not s.is_open)
        my = (s.id in my_slot_ids)

        # 제목(학생 화면)
        # - 시간 표시는 FullCalendar가 좌측에 자동 표시함(예: 13:00)
        # - 예약 현황은 (예약수/정원)으로 함께 표시
        if my:
            title = f"내 예약 ({s.starts_at.strftime('%H:%M')})"
        elif closed:
            title = "CLOSED"
        elif full:
            title = f"예약 마감 ({count}/{rnd.capacity})"
        else:
            title = f"예약 가능 ({count}/{rnd.capacity})"

        # 예약자 이름 표시 규칙
        names = ""
        if count > 0:
            if rnd.capacity == 1:
                names = "예약됨"  # 1:1에서는 이름 비공개
            else:
                names = ", ".join([u.display_name for u in us if u])

        events.append({
            "id": str(s.id),
            "title": title,
            "start": iso_dt(s.starts_at),
            "end": iso_dt(s.ends_at),
            "extendedProps": {
                "slotId": s.id,
                "isOpen": s.is_open,
                "count": count,
                "capacity": rnd.capacity,
                "my": my,
                "names": names,
                "startsAt": iso_dt(s.starts_at),
            }
        })
    return JSONResponse(events)


@app.post("/api/student/book/{slot_id}")
def api_student_book(slot_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if user.role != "student":
        raise HTTPException(403, "학생만")

    slot = db.get(Slot, slot_id)
    if not slot or not slot.is_open:
        raise HTTPException(404, "예약 불가 슬롯")

    rnd = db.get(ConsultationRound, slot.round_id)
    if not rnd:
        raise HTTPException(400, "Round 없음")

    if not cutoff_ok(slot.starts_at):
        raise HTTPException(400, "당일에는 예약/변경/취소 불가")

    if db.exec(select(Booking).where(Booking.slot_id == slot_id, Booking.user_id == user.id)).first():
        return JSONResponse({"ok": True, "msg": "이미 예약됨"})

    if slot_current_count(db, slot_id) >= rnd.capacity:
        raise HTTPException(400, "정원 초과")

    if count_my_round_bookings(db, user.id, rnd.id) >= rnd.max_per_student:
        raise HTTPException(400, f"해당 차수 예약 횟수 제한 초과 (현재 {count_my_round_bookings(db, user.id, rnd.id)}회 / 제한 {rnd.max_per_student}회). 기존 예약을 취소하거나 변경해줘.")

    db.add(Booking(slot_id=slot_id, user_id=user.id))
    try:
        db.commit()
    except OperationalError:
        db.rollback()
        raise HTTPException(500, "DB 스키마 오류(기존 mentoring.db). 서버를 완전히 재시작하거나 mentoring.db를 삭제 후 재실행해줘.")
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"예약 처리 중 오류: {e}")

    return JSONResponse({"ok": True, "msg": "예약 완료"})


@app.post("/api/student/cancel/{booking_id}")
def api_student_cancel(booking_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if user.role != "student":
        raise HTTPException(403, "학생만")

    b = db.get(Booking, booking_id)
    if not b or b.user_id != user.id:
        raise HTTPException(404, "예약 없음")

    slot = db.get(Slot, b.slot_id)
    if not slot:
        raise HTTPException(404, "슬롯 없음")

    if not cutoff_ok(slot.starts_at):
        raise HTTPException(400, "당일에는 예약/변경/취소 불가")

    db.delete(b)
    db.commit()
    return JSONResponse({"ok": True, "msg": "취소 완료"})


@app.post("/api/student/move")
def api_student_move(
    from_booking_id: int = Form(...),
    to_slot_id: int = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_user)
):
    if user.role != "student":
        raise HTTPException(403, "학생만")

    b = db.get(Booking, int(from_booking_id))
    if not b or b.user_id != user.id:
        raise HTTPException(404, "예약 없음")

    from_slot = db.get(Slot, b.slot_id)
    to_slot = db.get(Slot, int(to_slot_id))
    if not from_slot or not to_slot:
        raise HTTPException(404, "슬롯 없음")

    if from_slot.round_id != to_slot.round_id:
        raise HTTPException(400, "같은 차수 내에서만 변경 가능")

    rnd = db.get(ConsultationRound, from_slot.round_id)
    if not rnd:
        raise HTTPException(400, "Round 없음")

    if not cutoff_ok(from_slot.starts_at) or not cutoff_ok(to_slot.starts_at):
        raise HTTPException(400, "당일에는 예약/변경/취소 불가")

    if not to_slot.is_open:
        raise HTTPException(400, "닫힌 슬롯")

    if slot_current_count(db, to_slot.id) >= rnd.capacity:
        raise HTTPException(400, "정원 초과")

    b.slot_id = to_slot.id
    db.add(b)
    db.commit()
    return JSONResponse({"ok": True, "msg": "변경 완료"})


@app.post("/prof/slot/{slot_id}/delete")
def prof_delete_slot(slot_id: int, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    """슬롯 삭제(해당 슬롯의 예약도 함께 삭제)."""
    s = db.get(Slot, slot_id)
    if not s:
        raise HTTPException(404, "Slot 없음")
    for b in db.exec(select(Booking).where(Booking.slot_id == slot_id)).all():
        db.delete(b)
    db.delete(s)
    db.commit()
    return JSONResponse({"ok": True})


@app.post("/prof/round/{round_id}/slots/delete_all")
def prof_delete_all_slots(
    round_id: int,
    db: Session = Depends(get_db),
    prof: User = Depends(require_prof),
):
    """교수자: 특정 차수(round)의 슬롯/예약 전체 삭제."""
    rnd = db.get(ConsultationRound, round_id)
    if not rnd:
        raise HTTPException(404, "Round 없음")

    slot_ids = [s.id for s in db.exec(select(Slot).where(Slot.round_id == round_id)).all()]
    if slot_ids:
        db.exec(delete(Booking).where(Booking.slot_id.in_(slot_ids)))
        db.exec(delete(Slot).where(Slot.round_id == round_id))
        db.commit()

    return JSONResponse({"ok": True, "deleted_slots": len(slot_ids)})

@app.post("/prof/slot/{slot_id}/update_time")
def prof_update_slot_time(
    slot_id: int,
    starts_at: str = Form(...),  # "YYYY-MM-DD HH:MM" 또는 ISO
    ends_at: str = Form(...),
    db: Session = Depends(get_db),
    prof: User = Depends(require_prof)
):
    """슬롯 시간 수정."""
    s = db.get(Slot, slot_id)
    if not s:
        raise HTTPException(404, "Slot 없음")

    def parse_dt(v: str) -> datetime:
        v = v.strip()
        if "T" in v:
            dt = datetime.fromisoformat(v)
        else:
            dt = datetime.fromisoformat(v.replace(" ", "T"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=APP_TZ)
        return dt.astimezone(APP_TZ)

    st = parse_dt(starts_at)
    et = parse_dt(ends_at)
    if et <= st:
        raise HTTPException(400, "종료시간은 시작시간 이후여야 함")
    s.starts_at = st
    s.ends_at = et
    db.add(s)
    db.commit()
    return JSONResponse({"ok": True})

@app.get("/api/prof/round/{round_id}/slots_table")
def prof_slots_table(round_id: int, db: Session = Depends(get_db), prof: User = Depends(require_prof)):
    rnd = db.get(ConsultationRound, round_id)
    if not rnd:
        raise HTTPException(404, "Round 없음")
    slots = db.exec(select(Slot).where(Slot.round_id == round_id).order_by(Slot.starts_at)).all()
    users = {u.id: u for u in db.exec(select(User)).all()}
    bks = db.exec(select(Booking)).all()
    by_slot = {}
    for b in bks:
        by_slot.setdefault(b.slot_id, []).append(users.get(b.user_id))
    rows = []
    for s in slots:
        us = by_slot.get(s.id, [])
        rows.append({
            "slotId": s.id,
            "date": s.starts_at.astimezone(APP_TZ).strftime("%Y-%m-%d"),
            "time": f"{s.starts_at.strftime('%H:%M')}~{s.ends_at.strftime('%H:%M')}",
            "open": s.is_open,
            "count": len(us),
            "capacity": rnd.capacity,
            "names": ", ".join([u.display_name for u in us if u]) if us else "",
        })
    return JSONResponse(rows)

@app.get("/api/student/round/{round_id}/my_bookings")
def api_my_bookings(round_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if user.role != "student":
        raise HTTPException(403, "학생만")
    slots = db.exec(select(Slot).where(Slot.round_id == round_id)).all()
    slot_map = {s.id: s for s in slots}
    my = []
    for b in db.exec(select(Booking).where(Booking.user_id == user.id)).all():
        s = slot_map.get(b.slot_id)
        if not s:
            continue
        my.append({
            "bookingId": b.id,
            "slotId": s.id,
            "startsAt": iso_dt(s.starts_at),
            "endsAt": iso_dt(s.ends_at),
            "date": s.starts_at.astimezone(APP_TZ).strftime("%Y-%m-%d"),
            "time": f"{s.starts_at.strftime('%H:%M')}~{s.ends_at.strftime('%H:%M')}",
        })
    my.sort(key=lambda x: x["startsAt"])
    return JSONResponse(my)
