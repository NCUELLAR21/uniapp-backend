from sqlalchemy import (
    Column, Integer, String, ForeignKey, UniqueConstraint, Time, Text, Date, DateTime
)
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

class UserRole(Base):
    __tablename__ = "user_roles"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String, nullable=False, index=True)  # student | teacher
    __table_args__ = (UniqueConstraint("user_id", "role", name="uix_user_role_unique"),)

class Plan(Base):
    __tablename__ = "plans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    university_name = Column(String, nullable=False)
    career_name = Column(String, nullable=False)
    num_semesters = Column(Integer, nullable=False)

class Subject(Base):
    __tablename__ = "subjects"
    id = Column(Integer, primary_key=True, index=True)
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=False)
    name = Column(String, nullable=False)
    semester_number = Column(Integer, nullable=False)
    status = Column(String, default="pending", nullable=False)  # pending | current | passed
    __table_args__ = (UniqueConstraint("plan_id", "semester_number", "name", name="uix_plan_semester_subject"),)

class ClassSession(Base):
    __tablename__ = "class_sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    context = Column(String, nullable=False, default="student")  # student | teacher
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=True)
    subject_id = Column(Integer, ForeignKey("subjects.id"), nullable=True)
    subject_name = Column(String, nullable=False)
    institution = Column(String, nullable=False)
    location = Column(String, nullable=False)
    day_of_week = Column(Integer, nullable=False)  # 1=Lun ... 7=Dom
    start_time = Column(Time, nullable=False)
    end_time = Column(Time, nullable=False)
    notes = Column(Text, nullable=True)

class TeacherCourse(Base):
    __tablename__ = "teacher_courses"
    id = Column(Integer, primary_key=True, index=True)
    teacher_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    course_name = Column(String, nullable=False)
    institution = Column(String, nullable=False)
    status = Column(String, nullable=False, default="cursando", index=True)  # cursando | finalizado
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class TeacherCourseMeeting(Base):
    __tablename__ = "teacher_course_meetings"
    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("teacher_courses.id"), nullable=False, index=True)
    day_of_week = Column(Integer, nullable=False)
    start_time = Column(Time, nullable=False)
    end_time = Column(Time, nullable=False)
    modality = Column(String, nullable=False, default="presencial")  # presencial | online | hibrido
    location = Column(String, nullable=False, default="")
    notes = Column(Text, nullable=True)

class TeacherEvaluation(Base):
    __tablename__ = "teacher_evaluations"
    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("teacher_courses.id"), nullable=False, index=True)
    eval_number = Column(Integer, nullable=False)
    title = Column(String, nullable=False)
    date = Column(Date, nullable=False)
    status = Column(String, nullable=False, default="planificada", index=True)
    notes = Column(Text, nullable=True)
    __table_args__ = (UniqueConstraint("course_id", "eval_number", name="uix_course_eval_number"),)

class TeacherTask(Base):
    __tablename__ = "teacher_tasks"
    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("teacher_courses.id"), nullable=False, index=True)
    task_type = Column(String, nullable=False, default="otro", index=True)
    title = Column(String, nullable=False)
    due_date = Column(Date, nullable=True)
    status = Column(String, nullable=False, default="pendiente", index=True)
    priority = Column(String, nullable=False, default="med", index=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class TeacherCourseEvent(Base):
    __tablename__ = "teacher_course_events"
    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("teacher_courses.id"), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    event_at = Column(DateTime(timezone=True), nullable=False)
    remind_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, nullable=False, default="pendiente", index=True)  # pendiente | cumplida | cancelada
    priority = Column(String, nullable=False, default="med", index=True)  # low | med | high
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
