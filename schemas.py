from pydantic import BaseModel, field_validator
from typing import Optional, List, Literal
import re
from datetime import time, date, datetime

ALLOWED_ROLES = {"student", "teacher"}

class UserCreate(BaseModel):
    name: str
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str):
        v = v.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Email inválido")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str):
        if len(v) < 6:
            raise ValueError("password mínimo 6 caracteres")
        return v

class UserPatch(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]):
        if v is None:
            return v
        v = v.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Email inválido")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: Optional[str]):
        if v is None:
            return v
        if len(v) < 6:
            raise ValueError("password mínimo 6 caracteres")
        return v

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    class Config:
        from_attributes = True

class UserWithRolesResponse(UserResponse):
    roles: List[str]

class LoginRequest(BaseModel):
    email: str
    password: str
    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str):
        return v.strip().lower()

class LoginResponse(BaseModel):
    pre_token: str
    token_type: str = "bearer"
    user: UserResponse
    available_roles: List[str]

class SelectRoleRequest(BaseModel):
    role: str
    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str):
        v = v.strip().lower()
        if v not in ALLOWED_ROLES:
            raise ValueError("role debe ser student o teacher")
        return v

class SelectRoleResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    active_role: str
    user: UserResponse

class PlanCreate(BaseModel):
    user_id: int
    university_name: str
    career_name: str
    num_semesters: int

class PlanPatch(BaseModel):
    university_name: Optional[str] = None
    career_name: Optional[str] = None
    num_semesters: Optional[int] = None

class PlanResponse(BaseModel):
    id: int
    user_id: int
    university_name: str
    career_name: str
    num_semesters: int
    class Config:
        from_attributes = True

class SubjectCreate(BaseModel):
    name: str
    semester_number: int
    status: str = "pending"

class SubjectPatch(BaseModel):
    name: Optional[str] = None
    semester_number: Optional[int] = None
    status: Optional[str] = None

class SubjectResponse(BaseModel):
    id: int
    plan_id: int
    name: str
    semester_number: int
    status: str
    class Config:
        from_attributes = True

class ClassSessionCreate(BaseModel):
    user_id: int
    context: str = "student"
    plan_id: Optional[int] = None
    subject_id: Optional[int] = None
    subject_name: str
    institution: str
    location: str
    day_of_week: int
    start_time: time
    end_time: time
    notes: Optional[str] = None

class ClassSessionPatch(BaseModel):
    context: Optional[str] = None
    plan_id: Optional[int] = None
    subject_id: Optional[int] = None
    subject_name: Optional[str] = None
    institution: Optional[str] = None
    location: Optional[str] = None
    day_of_week: Optional[int] = None
    start_time: Optional[time] = None
    end_time: Optional[time] = None
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

class TeacherCourseCreate(BaseModel):
    course_name: str
    institution: str
    status: str = "cursando"

class TeacherCoursePatch(BaseModel):
    course_name: Optional[str] = None
    institution: Optional[str] = None
    status: Optional[str] = None

class TeacherCourseResponse(BaseModel):
    id: int
    teacher_user_id: int
    course_name: str
    institution: str
    status: str
    class Config:
        from_attributes = True

class TeacherCourseMeetingCreate(BaseModel):
    day_of_week: int
    start_time: time
    end_time: time
    modality: str = "presencial"
    location: str = ""
    notes: Optional[str] = None

class TeacherCourseMeetingPatch(BaseModel):
    day_of_week: Optional[int] = None
    start_time: Optional[time] = None
    end_time: Optional[time] = None
    modality: Optional[str] = None
    location: Optional[str] = None
    notes: Optional[str] = None

class TeacherCourseMeetingResponse(BaseModel):
    id: int
    course_id: int
    day_of_week: int
    start_time: time
    end_time: time
    modality: str
    location: str
    notes: Optional[str] = None
    class Config:
        from_attributes = True

class TeacherEvaluationCreate(BaseModel):
    eval_number: int
    title: str
    date: date
    status: str = "planificada"
    notes: Optional[str] = None

class TeacherEvaluationPatch(BaseModel):
    eval_number: Optional[int] = None
    title: Optional[str] = None
    date: date | None = None
    status: Optional[str] = None
    notes: Optional[str] = None

class TeacherEvaluationResponse(BaseModel):
    id: int
    course_id: int
    eval_number: int
    title: str
    date: date
    status: str
    notes: Optional[str] = None
    class Config:
        from_attributes = True

class TeacherTaskCreate(BaseModel):
    task_type: str = "otro"
    title: str
    due_date: Optional[date] = None
    status: str = "pendiente"
    priority: str = "med"
    notes: Optional[str] = None

class TeacherTaskPatch(BaseModel):
    task_type: Optional[str] = None
    title: Optional[str] = None
    due_date: Optional[date] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    notes: Optional[str] = None

class TeacherTaskResponse(BaseModel):
    id: int
    course_id: int
    task_type: str
    title: str
    due_date: Optional[date] = None
    status: str
    priority: str
    notes: Optional[str] = None
    class Config:
        from_attributes = True

TeacherEventStatus = Literal["pendiente", "cumplida", "cancelada"]
TeacherEventPriority = Literal["low", "med", "high"]

class TeacherCourseEventCreate(BaseModel):
    title: str
    description: Optional[str] = None
    event_at: datetime
    remind_at: Optional[datetime] = None
    status: TeacherEventStatus = "pendiente"
    priority: TeacherEventPriority = "med"

class TeacherCourseEventUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    event_at: Optional[datetime] = None
    remind_at: Optional[datetime] = None
    status: Optional[TeacherEventStatus] = None
    priority: Optional[TeacherEventPriority] = None
    completed_at: Optional[datetime] = None

class TeacherCourseEventResponse(BaseModel):
    id: int
    course_id: int
    title: str
    description: Optional[str] = None
    event_at: datetime
    remind_at: Optional[datetime] = None
    status: TeacherEventStatus
    priority: TeacherEventPriority
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    class Config:
        from_attributes = True

class TeacherScheduleItem(BaseModel):
    course_id: int
    course_name: str
    institution: str
    status: str
    meeting_id: int
    day_of_week: int
    start_time: time
    end_time: time
    modality: str
    location: str
    notes: Optional[str] = None
