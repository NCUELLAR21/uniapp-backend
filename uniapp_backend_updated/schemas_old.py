from pydantic import BaseModel, field_validator
from typing import Optional
import re
from datetime import time

# =========================
# USERS
# =========================

class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    role: str = "student"   # student | teacher

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str):
        v = v.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Email inválido")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str):
        v = v.strip().lower()
        if v not in {"student", "teacher"}:
            raise ValueError("role debe ser student o teacher")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str):
        if len(v) < 6:
            raise ValueError("password mínimo 6 caracteres")
        return v


class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str):
        return v.strip().lower()


# =========================
# PLANS
# =========================

class PlanCreate(BaseModel):
    user_id: int
    university_name: str
    career_name: str
    num_semesters: int


class PlanResponse(BaseModel):
    id: int
    user_id: int
    university_name: str
    career_name: str
    num_semesters: int

    class Config:
        from_attributes = True


# =========================
# SUBJECTS
# =========================

class SubjectCreate(BaseModel):
    name: str
    semester_number: int
    status: str = "pending"   # pending | current | passed


class SubjectResponse(BaseModel):
    id: int
    plan_id: int
    name: str
    semester_number: int
    status: str

    class Config:
        from_attributes = True


# =========================
# CLASS SESSIONS (HORARIO)
# =========================

class ClassSessionCreate(BaseModel):
    user_id: int
    context: str = "student"     # student | teacher
    plan_id: Optional[int] = None
    subject_id: Optional[int] = None
    subject_name: str
    institution: str
    location: str
    day_of_week: int             # 1=Lun ... 7=Dom
    start_time: time
    end_time: time
    notes: Optional[str] = None


class ClassSessionResponse(BaseModel):
    id: int
    user_id: int
    context: str
    plan_id: Optional[int] = None
    subject_id: Optional[int] = None
    subject_name: str
    institution: str
    location: str
    day_of_week: int
    start_time: time
    end_time: time
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class TodayClassResponse(BaseModel):
    has_class: bool
    message: Optional[str] = None
    class_session: Optional[ClassSessionResponse] = None
