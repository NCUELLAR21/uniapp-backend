from fastapi import FastAPI, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List, Optional
from datetime import datetime, timedelta
import os
import hashlib
import bcrypt

import models
from database import engine, SessionLocal
from schemas import (
    ALLOWED_ROLES,
    UserCreate, UserPatch, UserResponse, UserWithRolesResponse,
    LoginRequest, LoginResponse,
    SelectRoleRequest, SelectRoleResponse,

    PlanCreate, PlanPatch, PlanResponse,
    SubjectCreate, SubjectPatch, SubjectResponse,

    ClassSessionCreate, ClassSessionPatch, ClassSessionResponse,
    TodayClassResponse,

    TeacherCourseCreate, TeacherCoursePatch, TeacherCourseResponse,
    TeacherCourseMeetingCreate, TeacherCourseMeetingPatch, TeacherCourseMeetingResponse,
    TeacherEvaluationCreate, TeacherEvaluationPatch, TeacherEvaluationResponse,
    TeacherTaskCreate, TeacherTaskPatch, TeacherTaskResponse,
    TeacherCourseEventCreate, TeacherCourseEventUpdate, TeacherCourseEventResponse,
    TeacherScheduleItem,
)

app = FastAPI(title="UniApp API (Dynamic Roles + Full CRUD)")
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
# PASSWORD (bcrypt + prehash SHA-256)
# =========================
def _prehash_bytes(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()

def hash_password(password: str) -> str:
    pw = _prehash_bytes(password)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw, salt).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    try:
        pw = _prehash_bytes(password)
        return bcrypt.checkpw(pw, hashed.encode("utf-8"))
    except Exception:
        return False

# =========================
# JWT AUTH (2 steps)
# =========================
SECRET_KEY = os.getenv("UNIAPP_SECRET_KEY", "CAMBIA_ESTO_POR_UN_SECRETO_LARGO_Y_RANDOM")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
PRE_TOKEN_EXPIRE_MINUTES = 10

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def _create_token(*, user_id: int, token_type: str, active_role: Optional[str] = None, minutes: int = 60) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "typ": token_type,   # pre | access
        "iat": int(now.timestamp()),
        "exp": now + timedelta(minutes=minutes),
    }
    if active_role is not None:
        payload["active_role"] = active_role
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def _decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

class AuthContext:
    def __init__(self, user: models.User, active_role: str):
        self.user = user
        self.active_role = active_role
    def __getattr__(self, item):
        return getattr(self.user, item)

def get_pre_auth_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    cred_exc = HTTPException(status_code=401, detail="Token inválido o expirado")
    try:
        payload = _decode_token(token)
        if payload.get("typ") != "pre":
            raise cred_exc
        user_id = int(payload.get("sub"))
    except (JWTError, ValueError, TypeError):
        raise cred_exc

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise cred_exc
    return user

def get_current_auth(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> AuthContext:
    cred_exc = HTTPException(status_code=401, detail="Token inválido o expirado")
    try:
        payload = _decode_token(token)
        if payload.get("typ") != "access":
            raise cred_exc
        user_id = int(payload.get("sub"))
        active_role = payload.get("active_role")
        if not active_role:
            raise cred_exc
    except (JWTError, ValueError, TypeError):
        raise cred_exc

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise cred_exc

    # Validación: rol del token debe existir en DB
    has_role = db.query(models.UserRole).filter(
        models.UserRole.user_id == user_id,
        models.UserRole.role == active_role
    ).first()
    if not has_role:
        raise HTTPException(status_code=401, detail="Rol del token no es válido para este usuario")

    return AuthContext(user=user, active_role=active_role)

def require_teacher(ctx: AuthContext = Depends(get_current_auth)) -> AuthContext:
    if ctx.active_role != "teacher":
        raise HTTPException(status_code=403, detail="Solo docentes (active_role=teacher)")
    return ctx

# =========================
# ROOT
# =========================
@app.get("/")
def root():
    return {"message": "UniApp API funcionando 🚀", "docs": "/docs"}

# =========================
# HELPERS
# =========================
def _get_user_or_404(user_id: int, db: Session) -> models.User:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user

def _get_user_roles(user_id: int, db: Session) -> List[str]:
    rows = db.query(models.UserRole.role).filter(models.UserRole.user_id == user_id).all()
    return sorted({r[0] for r in rows})

def _ensure_default_student_role(user_id: int, db: Session):
    exists = db.query(models.UserRole).filter(models.UserRole.user_id == user_id, models.UserRole.role == "student").first()
    if not exists:
        db.add(models.UserRole(user_id=user_id, role="student"))
        db.commit()

def _get_plan_or_404(plan_id: int, db: Session) -> models.Plan:
    plan = db.query(models.Plan).filter(models.Plan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    return plan

def _get_subject_or_404(subject_id: int, db: Session) -> models.Subject:
    subj = db.query(models.Subject).filter(models.Subject.id == subject_id).first()
    if not subj:
        raise HTTPException(status_code=404, detail="Ramo no encontrado")
    return subj

def _get_class_session_or_404(session_id: int, db: Session) -> models.ClassSession:
    sess = db.query(models.ClassSession).filter(models.ClassSession.id == session_id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Sesión de horario no encontrada")
    return sess

def _get_course_or_404(course_id: int, db: Session) -> models.TeacherCourse:
    course = db.query(models.TeacherCourse).filter(models.TeacherCourse.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Curso docente no encontrado")
    return course

def _get_meeting_or_404(meeting_id: int, db: Session) -> models.TeacherCourseMeeting:
    m = db.query(models.TeacherCourseMeeting).filter(models.TeacherCourseMeeting.id == meeting_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Bloque/meeting no encontrado")
    return m

def _get_evaluation_or_404(evaluation_id: int, db: Session) -> models.TeacherEvaluation:
    e = db.query(models.TeacherEvaluation).filter(models.TeacherEvaluation.id == evaluation_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Evaluación no encontrada")
    return e

def _get_task_or_404(task_id: int, db: Session) -> models.TeacherTask:
    t = db.query(models.TeacherTask).filter(models.TeacherTask.id == task_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    return t

def _get_event_or_404(event_id: int, db: Session) -> models.TeacherCourseEvent:
    e = db.query(models.TeacherCourseEvent).filter(models.TeacherCourseEvent.id == event_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Evento no encontrado")
    return e

# =========================
# USERS
# =========================
@app.post("/users", response_model=UserWithRolesResponse)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    email = user.email.strip().lower()
    exists = db.query(models.User).filter(models.User.email == email).first()
    if exists:
        raise HTTPException(status_code=409, detail="Email ya registrado")

    db_user = models.User(
        name=user.name.strip(),
        email=email,
        password_hash=hash_password(user.password),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    _ensure_default_student_role(db_user.id, db)
    roles = _get_user_roles(db_user.id, db)
    return UserWithRolesResponse(id=db_user.id, name=db_user.name, email=db_user.email, roles=roles)

@app.get("/users/me", response_model=UserWithRolesResponse)
def get_me(ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    roles = _get_user_roles(ctx.id, db)
    return UserWithRolesResponse(id=ctx.id, name=ctx.name, email=ctx.email, roles=roles)

@app.patch("/users/me", response_model=UserWithRolesResponse)
def patch_me(payload: UserPatch, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    user = _get_user_or_404(ctx.id, db)

    if payload.name is not None:
        user.name = payload.name.strip()

    if payload.email is not None:
        new_email = payload.email.strip().lower()
        exists = db.query(models.User).filter(models.User.email == new_email, models.User.id != ctx.id).first()
        if exists:
            raise HTTPException(status_code=409, detail="Email ya está en uso por otro usuario")
        user.email = new_email

    if payload.password is not None:
        user.password_hash = hash_password(payload.password)

    db.commit()
    db.refresh(user)

    roles = _get_user_roles(ctx.id, db)
    return UserWithRolesResponse(id=user.id, name=user.name, email=user.email, roles=roles)

# DEV: habilitar roles a sí mismo (para avanzar rápido)
@app.post("/users/me/roles/{role}", response_model=UserWithRolesResponse)
def add_role_to_me(role: str, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    role = role.strip().lower()
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail="Rol inválido (student|teacher)")

    exists = db.query(models.UserRole).filter(models.UserRole.user_id == ctx.id, models.UserRole.role == role).first()
    if not exists:
        db.add(models.UserRole(user_id=ctx.id, role=role))
        db.commit()

    roles = _get_user_roles(ctx.id, db)
    return UserWithRolesResponse(id=ctx.id, name=ctx.name, email=ctx.email, roles=roles)

# =========================
# AUTH (2 steps)
# =========================
@app.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    roles = _get_user_roles(user.id, db)
    pre_token = _create_token(user_id=user.id, token_type="pre", minutes=PRE_TOKEN_EXPIRE_MINUTES)
    return LoginResponse(pre_token=pre_token, user=user, available_roles=roles)

@app.post("/auth/select-role", response_model=SelectRoleResponse)
def select_role(payload: SelectRoleRequest, user: models.User = Depends(get_pre_auth_user), db: Session = Depends(get_db)):
    role = payload.role.strip().lower()
    has_role = db.query(models.UserRole).filter(models.UserRole.user_id == user.id, models.UserRole.role == role).first()
    if not has_role:
        raise HTTPException(status_code=403, detail="El usuario no tiene ese rol habilitado")

    access_token = _create_token(user_id=user.id, token_type="access", active_role=role, minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return SelectRoleResponse(access_token=access_token, active_role=role, user=user)

# =========================
# PLANS (CRUD)
# =========================
@app.post("/plans", response_model=PlanResponse)
def create_plan(plan: PlanCreate, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes crear planes para otro usuario")

    db_plan = models.Plan(**plan.model_dump())
    db.add(db_plan)
    db.commit()
    db.refresh(db_plan)
    return db_plan

@app.get("/plans", response_model=List[PlanResponse])
def list_plans(ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    return db.query(models.Plan).filter(models.Plan.user_id == ctx.id).order_by(models.Plan.id.desc()).all()

@app.get("/plans/{plan_id}", response_model=PlanResponse)
def get_plan(plan_id: int, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    plan = _get_plan_or_404(plan_id, db)
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver este plan")
    return plan

@app.patch("/plans/{plan_id}", response_model=PlanResponse)
def patch_plan(plan_id: int, payload: PlanPatch, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    plan = _get_plan_or_404(plan_id, db)
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar este plan")

    if payload.university_name is not None:
        plan.university_name = payload.university_name.strip()
    if payload.career_name is not None:
        plan.career_name = payload.career_name.strip()
    if payload.num_semesters is not None:
        plan.num_semesters = payload.num_semesters

    db.commit()
    db.refresh(plan)
    return plan

@app.delete("/plans/{plan_id}", status_code=204)
def delete_plan(plan_id: int, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    plan = _get_plan_or_404(plan_id, db)
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para borrar este plan")

    # Borrar subjects del plan primero (SQLite sin cascade configurado)
    db.query(models.Subject).filter(models.Subject.plan_id == plan_id).delete()
    db.delete(plan)
    db.commit()
    return Response(status_code=204)

# =========================
# SUBJECTS (CRUD)
# =========================
@app.post("/plans/{plan_id}/subjects", response_model=SubjectResponse)
def create_subject(plan_id: int, subject: SubjectCreate, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    plan = _get_plan_or_404(plan_id, db)
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes crear ramos para otro usuario")

    db_subject = models.Subject(plan_id=plan_id, **subject.model_dump())
    db.add(db_subject)
    try:
        db.commit()
        db.refresh(db_subject)
        return db_subject
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Ramo duplicado (unique)")

@app.get("/plans/{plan_id}/subjects", response_model=List[SubjectResponse])
def list_subjects(plan_id: int, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    plan = _get_plan_or_404(plan_id, db)
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver ramos de este plan")
    return db.query(models.Subject).filter(models.Subject.plan_id == plan_id).order_by(models.Subject.semester_number, models.Subject.name).all()

@app.get("/subjects/{subject_id}", response_model=SubjectResponse)
def get_subject(subject_id: int, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    subj = _get_subject_or_404(subject_id, db)
    plan = _get_plan_or_404(subj.plan_id, db)
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver este ramo")
    return subj

@app.patch("/subjects/{subject_id}", response_model=SubjectResponse)
def patch_subject(subject_id: int, payload: SubjectPatch, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    subj = _get_subject_or_404(subject_id, db)
    plan = _get_plan_or_404(subj.plan_id, db)
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar este ramo")

    if payload.name is not None:
        subj.name = payload.name.strip()
    if payload.semester_number is not None:
        subj.semester_number = payload.semester_number
    if payload.status is not None:
        subj.status = payload.status.strip().lower()

    try:
        db.commit()
        db.refresh(subj)
        return subj
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Conflicto: ramo duplicado (unique)")

@app.delete("/subjects/{subject_id}", status_code=204)
def delete_subject(subject_id: int, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    subj = _get_subject_or_404(subject_id, db)
    plan = _get_plan_or_404(subj.plan_id, db)
    if plan.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para borrar este ramo")

    db.delete(subj)
    db.commit()
    return Response(status_code=204)

# =========================
# CLASS SESSIONS (CRUD)
# =========================
@app.post("/schedule/sessions", response_model=ClassSessionResponse)
def create_class_session(payload: ClassSessionCreate, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    if payload.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes crear sesiones para otro usuario")

    sess = models.ClassSession(**payload.model_dump())
    db.add(sess)
    db.commit()
    db.refresh(sess)
    return sess

@app.get("/schedule/sessions", response_model=List[ClassSessionResponse])
def list_class_sessions(
    user_id: int,
    context: Optional[str] = None,
    day_of_week: Optional[int] = None,
    ctx: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db)
):
    if user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver horarios de otro usuario")

    q = db.query(models.ClassSession).filter(models.ClassSession.user_id == user_id)
    if context:
        q = q.filter(models.ClassSession.context == context)
    if day_of_week is not None:
        q = q.filter(models.ClassSession.day_of_week == day_of_week)

    return q.order_by(models.ClassSession.day_of_week, models.ClassSession.start_time).all()

@app.get("/schedule/sessions/{session_id}", response_model=ClassSessionResponse)
def get_class_session(session_id: int, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    sess = _get_class_session_or_404(session_id, db)
    if sess.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver esta sesión")
    return sess

@app.patch("/schedule/sessions/{session_id}", response_model=ClassSessionResponse)
def patch_class_session(session_id: int, payload: ClassSessionPatch, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    sess = _get_class_session_or_404(session_id, db)
    if sess.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes editar sesiones de otro usuario")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(sess, field, value)

    db.commit()
    db.refresh(sess)
    return sess

@app.delete("/schedule/sessions/{session_id}", status_code=204)
def delete_class_session(session_id: int, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    sess = _get_class_session_or_404(session_id, db)
    if sess.user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes borrar sesiones de otro usuario")

    db.delete(sess)
    db.commit()
    return Response(status_code=204)

@app.get("/schedule/today/{user_id}", response_model=TodayClassResponse)
def get_today_schedule(user_id: int, context: Optional[str] = None, ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    if user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver horarios de otro usuario")

    day = datetime.now().isoweekday()
    q = db.query(models.ClassSession).filter(models.ClassSession.user_id == user_id, models.ClassSession.day_of_week == day)
    if context:
        q = q.filter(models.ClassSession.context == context)
    classes = q.order_by(models.ClassSession.start_time).all()

    if not classes:
        return TodayClassResponse(has_class=False, message="No hay clases programadas para hoy", class_session=None)

    return TodayClassResponse(has_class=True, class_session=classes[0])

# =========================================================
# TEACHER MODULE (FULL CRUD) - requires active_role=teacher
# =========================================================
@app.post("/teacher/courses", response_model=TeacherCourseResponse)
def create_teacher_course(payload: TeacherCourseCreate, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = models.TeacherCourse(
        teacher_user_id=ctx.id,
        course_name=payload.course_name.strip(),
        institution=payload.institution.strip(),
        status=payload.status.strip().lower(),
    )
    db.add(course)
    db.commit()
    db.refresh(course)
    return course

@app.get("/teacher/courses", response_model=List[TeacherCourseResponse])
def list_teacher_courses(status: Optional[str] = None, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    q = db.query(models.TeacherCourse).filter(models.TeacherCourse.teacher_user_id == ctx.id)
    if status:
        q = q.filter(models.TeacherCourse.status == status.strip().lower())
    return q.order_by(models.TeacherCourse.id.desc()).all()

@app.get("/teacher/courses/{course_id}", response_model=TeacherCourseResponse)
def get_teacher_course(course_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver este curso")
    return course

@app.patch("/teacher/courses/{course_id}", response_model=TeacherCourseResponse)
def patch_teacher_course(course_id: int, payload: TeacherCoursePatch, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar este curso")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(course, field, value)

    db.commit()
    db.refresh(course)
    return course

@app.delete("/teacher/courses/{course_id}", status_code=204)
def delete_teacher_course(course_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para borrar este curso")

    # borrar dependencias primero
    db.query(models.TeacherCourseMeeting).filter(models.TeacherCourseMeeting.course_id == course_id).delete()
    db.query(models.TeacherEvaluation).filter(models.TeacherEvaluation.course_id == course_id).delete()
    db.query(models.TeacherTask).filter(models.TeacherTask.course_id == course_id).delete()
    db.query(models.TeacherCourseEvent).filter(models.TeacherCourseEvent.course_id == course_id).delete()
    db.delete(course)
    db.commit()
    return Response(status_code=204)

# Meetings
@app.post("/teacher/courses/{course_id}/meetings", response_model=TeacherCourseMeetingResponse)
def create_meeting(course_id: int, payload: TeacherCourseMeetingCreate, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes agregar meetings a cursos de otro docente")

    meeting = models.TeacherCourseMeeting(course_id=course_id, **payload.model_dump())
    db.add(meeting)
    db.commit()
    db.refresh(meeting)
    return meeting

@app.get("/teacher/courses/{course_id}/meetings", response_model=List[TeacherCourseMeetingResponse])
def list_meetings(course_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver meetings de este curso")
    return db.query(models.TeacherCourseMeeting).filter(models.TeacherCourseMeeting.course_id == course_id)\
        .order_by(models.TeacherCourseMeeting.day_of_week, models.TeacherCourseMeeting.start_time).all()

@app.patch("/teacher/meetings/{meeting_id}", response_model=TeacherCourseMeetingResponse)
def patch_meeting(meeting_id: int, payload: TeacherCourseMeetingPatch, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    meeting = _get_meeting_or_404(meeting_id, db)
    course = _get_course_or_404(meeting.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar este meeting")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(meeting, field, value)

    db.commit()
    db.refresh(meeting)
    return meeting

@app.delete("/teacher/meetings/{meeting_id}", status_code=204)
def delete_meeting(meeting_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    meeting = _get_meeting_or_404(meeting_id, db)
    course = _get_course_or_404(meeting.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para borrar este meeting")

    db.delete(meeting)
    db.commit()
    return Response(status_code=204)

# Evaluations
@app.post("/teacher/courses/{course_id}/evaluations", response_model=TeacherEvaluationResponse)
def create_evaluation(course_id: int, payload: TeacherEvaluationCreate, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes agregar evaluaciones a cursos de otro docente")

    ev = models.TeacherEvaluation(course_id=course_id, **payload.model_dump())
    db.add(ev)
    try:
        db.commit()
        db.refresh(ev)
        return ev
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Ya existe una evaluación con ese número en este curso")

@app.get("/teacher/courses/{course_id}/evaluations", response_model=List[TeacherEvaluationResponse])
def list_evaluations(course_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver evaluaciones de este curso")
    return db.query(models.TeacherEvaluation).filter(models.TeacherEvaluation.course_id == course_id)\
        .order_by(models.TeacherEvaluation.date, models.TeacherEvaluation.eval_number).all()

@app.patch("/teacher/evaluations/{evaluation_id}", response_model=TeacherEvaluationResponse)
def patch_evaluation(evaluation_id: int, payload: TeacherEvaluationPatch, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    ev = _get_evaluation_or_404(evaluation_id, db)
    course = _get_course_or_404(ev.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar esta evaluación")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(ev, field, value)

    try:
        db.commit()
        db.refresh(ev)
        return ev
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Conflicto: eval_number duplicado en este curso")

@app.delete("/teacher/evaluations/{evaluation_id}", status_code=204)
def delete_evaluation(evaluation_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    ev = _get_evaluation_or_404(evaluation_id, db)
    course = _get_course_or_404(ev.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para borrar esta evaluación")

    db.delete(ev)
    db.commit()
    return Response(status_code=204)

# Tasks
@app.post("/teacher/courses/{course_id}/tasks", response_model=TeacherTaskResponse)
def create_task(course_id: int, payload: TeacherTaskCreate, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes agregar tareas a cursos de otro docente")

    task = models.TeacherTask(course_id=course_id, **payload.model_dump())
    db.add(task)
    db.commit()
    db.refresh(task)
    return task

@app.get("/teacher/courses/{course_id}/tasks", response_model=List[TeacherTaskResponse])
def list_tasks(course_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver tareas de este curso")
    return db.query(models.TeacherTask).filter(models.TeacherTask.course_id == course_id)\
        .order_by(models.TeacherTask.created_at.desc()).all()

@app.patch("/teacher/tasks/{task_id}", response_model=TeacherTaskResponse)
def patch_task(task_id: int, payload: TeacherTaskPatch, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    task = _get_task_or_404(task_id, db)
    course = _get_course_or_404(task.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar esta tarea")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(task, field, value)

    db.commit()
    db.refresh(task)
    return task

@app.delete("/teacher/tasks/{task_id}", status_code=204)
def delete_task(task_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    task = _get_task_or_404(task_id, db)
    course = _get_course_or_404(task.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para borrar esta tarea")

    db.delete(task)
    db.commit()
    return Response(status_code=204)

# Events
@app.get("/teacher/courses/{course_id}/events", response_model=List[TeacherCourseEventResponse])
def list_events(course_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver eventos de este curso")
    return db.query(models.TeacherCourseEvent).filter(models.TeacherCourseEvent.course_id == course_id)\
        .order_by(models.TeacherCourseEvent.event_at).all()

@app.post("/teacher/courses/{course_id}/events", response_model=TeacherCourseEventResponse)
def create_event(course_id: int, payload: TeacherCourseEventCreate, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    course = _get_course_or_404(course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No puedes agregar eventos a cursos de otro docente")

    ev = models.TeacherCourseEvent(course_id=course_id, **payload.model_dump())
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev

@app.get("/teacher/events/{event_id}", response_model=TeacherCourseEventResponse)
def get_event(event_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    ev = _get_event_or_404(event_id, db)
    course = _get_course_or_404(ev.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver este evento")
    return ev

@app.put("/teacher/events/{event_id}", response_model=TeacherCourseEventResponse)
def update_event(event_id: int, payload: TeacherCourseEventUpdate, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    ev = _get_event_or_404(event_id, db)
    course = _get_course_or_404(ev.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar este evento")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(ev, field, value)

    db.commit()
    db.refresh(ev)
    return ev

@app.delete("/teacher/events/{event_id}", status_code=204)
def delete_event(event_id: int, ctx: AuthContext = Depends(require_teacher), db: Session = Depends(get_db)):
    ev = _get_event_or_404(event_id, db)
    course = _get_course_or_404(ev.course_id, db)
    if course.teacher_user_id != ctx.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para borrar este evento")

    db.delete(ev)
    db.commit()
    return Response(status_code=204)

# Teacher Schedule
@app.get("/teacher/schedule", response_model=List[TeacherScheduleItem])
def teacher_schedule(
    day_of_week: Optional[int] = None,
    only_status: str = "cursando",
    ctx: AuthContext = Depends(require_teacher),
    db: Session = Depends(get_db)
):
    q = (
        db.query(models.TeacherCourse, models.TeacherCourseMeeting)
        .join(models.TeacherCourseMeeting, models.TeacherCourseMeeting.course_id == models.TeacherCourse.id)
        .filter(models.TeacherCourse.teacher_user_id == ctx.id)
    )
    if only_status:
        q = q.filter(models.TeacherCourse.status == only_status.strip().lower())
    if day_of_week is not None:
        q = q.filter(models.TeacherCourseMeeting.day_of_week == day_of_week)

    rows = q.order_by(models.TeacherCourseMeeting.day_of_week, models.TeacherCourseMeeting.start_time).all()
    return [
        TeacherScheduleItem(
            course_id=c.id, course_name=c.course_name, institution=c.institution, status=c.status,
            meeting_id=m.id, day_of_week=m.day_of_week,
            start_time=m.start_time, end_time=m.end_time,
            modality=m.modality, location=m.location, notes=m.notes
        )
        for (c, m) in rows
    ]
@app.post("/auth/enable-role", response_model=UserWithRolesResponse)
def enable_role(payload: SelectRoleRequest, user: models.User = Depends(get_pre_auth_user), db: Session = Depends(get_db)):
    role = payload.role.strip().lower()
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail="Rol inválido (student|teacher)")

    exists = db.query(models.UserRole).filter(
        models.UserRole.user_id == user.id,
        models.UserRole.role == role
    ).first()

    if not exists:
        db.add(models.UserRole(user_id=user.id, role=role))
        db.commit()

    roles = _get_user_roles(user.id, db)
    return UserWithRolesResponse(id=user.id, name=user.name, email=user.email, roles=roles)
