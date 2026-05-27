from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, OperationalError
from typing import List, Optional
from datetime import datetime
import hashlib
import bcrypt  # ✅ bcrypt directo (NO passlib)

import models
from database import engine, SessionLocal
from schemas import (
    UserCreate, UserResponse, LoginRequest,
    PlanCreate, PlanResponse,
    SubjectCreate, SubjectResponse,
    ClassSessionCreate, ClassSessionResponse,
    TodayClassResponse
)

app = FastAPI(title="UniApp API")

models.Base.metadata.create_all(bind=engine)

# =========================
# DB
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# PASSWORD (bcrypt FIX + sin passlib)
# =========================
def _prehash_bytes(password: str) -> bytes:
    """
    Prehash SHA-256 en bytes (32 bytes) para:
    - evitar límites raros
    - evitar problemas con unicode/emojis
    - estandarizar entrada a bcrypt
    """
    return hashlib.sha256(password.encode("utf-8")).digest()

def hash_password(password: str) -> str:
    pw = _prehash_bytes(password)
    salt = bcrypt.gensalt()  # por defecto cost seguro
    hashed = bcrypt.hashpw(pw, salt)
    return hashed.decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    try:
        pw = _prehash_bytes(password)
        return bcrypt.checkpw(pw, hashed.encode("utf-8"))
    except Exception:
        return False

# =========================
# ROOT
# =========================
@app.get("/")
def root():
    return {"message": "API UniApp funcionando 🚀"}

# =========================
# USERS
# =========================
@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        email = user.email.strip().lower()

        exists = db.query(models.User).filter(models.User.email == email).first()
        if exists:
            raise HTTPException(status_code=409, detail="Email ya registrado")

        db_user = models.User(
            name=user.name.strip(),
            email=email,
            role=user.role,
            password_hash=hash_password(user.password),
        )

        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user

    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Conflicto guardando usuario (probable email duplicado)")

    except OperationalError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error SQLite: {str(e)}")

    except HTTPException:
        raise

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error inesperado creando usuario: {str(e)}")

@app.get("/users", response_model=List[UserResponse])
def get_users(db: Session = Depends(get_db)):
    return db.query(models.User).all()

# =========================
# AUTH
# =========================
@app.post("/auth/login", response_model=UserResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(models.User).filter(models.User.email == email).first()

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    return user

# =========================
# PLANS
# =========================
@app.post("/plans", response_model=PlanResponse)
def create_plan(plan: PlanCreate, db: Session = Depends(get_db)):
    try:
        db_plan = models.Plan(**plan.model_dump())
        db.add(db_plan)
        db.commit()
        db.refresh(db_plan)
        return db_plan
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creando plan: {str(e)}")

# =========================
# SUBJECTS
# =========================
@app.post("/plans/{plan_id}/subjects", response_model=SubjectResponse)
def create_subject(plan_id: int, subject: SubjectCreate, db: Session = Depends(get_db)):
    try:
        db_subject = models.Subject(plan_id=plan_id, **subject.model_dump())
        db.add(db_subject)
        db.commit()
        db.refresh(db_subject)
        return db_subject
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creando ramo: {str(e)}")

@app.get("/plans/{plan_id}/subjects", response_model=List[SubjectResponse])
def get_subjects_by_plan(plan_id: int, db: Session = Depends(get_db)):
    return db.query(models.Subject).filter(models.Subject.plan_id == plan_id).all()

# =========================
# CLASS SESSIONS (HORARIO)
# =========================
@app.post("/schedule/sessions", response_model=ClassSessionResponse)
def create_class_session(payload: ClassSessionCreate, db: Session = Depends(get_db)):
    try:
        session = models.ClassSession(**payload.model_dump())
        db.add(session)
        db.commit()
        db.refresh(session)
        return session
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creando sesión de horario: {str(e)}")

@app.get("/schedule/sessions", response_model=List[ClassSessionResponse])
def get_class_sessions(
    user_id: int,
    context: Optional[str] = None,
    day_of_week: Optional[int] = None,
    db: Session = Depends(get_db)
):
    q = db.query(models.ClassSession).filter(models.ClassSession.user_id == user_id)

    if context:
        q = q.filter(models.ClassSession.context == context)

    if day_of_week is not None:
        q = q.filter(models.ClassSession.day_of_week == day_of_week)

    return q.order_by(models.ClassSession.day_of_week, models.ClassSession.start_time).all()

@app.get("/schedule/today/{user_id}", response_model=TodayClassResponse)
def get_today_schedule(
    user_id: int,
    context: Optional[str] = None,
    db: Session = Depends(get_db)
):
    day_of_week = datetime.now().isoweekday()

    q = db.query(models.ClassSession).filter(
        models.ClassSession.user_id == user_id,
        models.ClassSession.day_of_week == day_of_week
    )

    if context:
        q = q.filter(models.ClassSession.context == context)

    classes = q.order_by(models.ClassSession.start_time).all()

    if not classes:
        return TodayClassResponse(
            has_class=False,
            message="No hay clases programadas para hoy",
            class_session=None
        )

    return TodayClassResponse(has_class=True, class_session=classes[0])
