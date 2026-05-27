from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint, Time, Text
from database import Base

# ---------- USERS ----------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)

    # student | teacher
    role = Column(String, nullable=False, default="student")

    # password hasheada (bcrypt)
    password_hash = Column(String, nullable=False)


# ---------- PLANS ----------
class Plan(Base):
    __tablename__ = "plans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    university_name = Column(String, nullable=False)
    career_name = Column(String, nullable=False)
    num_semesters = Column(Integer, nullable=False)


# ---------- SUBJECTS (RAMOS) ----------
class Subject(Base):
    __tablename__ = "subjects"

    id = Column(Integer, primary_key=True, index=True)
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=False)

    name = Column(String, nullable=False)
    semester_number = Column(Integer, nullable=False)

    # pending | current | passed
    status = Column(String, default="pending", nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "plan_id",
            "semester_number",
            "name",
            name="uix_plan_semester_subject"
        ),
    )


# ---------- CLASS SESSIONS (HORARIO) ----------
class ClassSession(Base):
    __tablename__ = "class_sessions"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # "student" | "teacher" (contexto)
    context = Column(String, nullable=False, default="student")

    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=True)
    subject_id = Column(Integer, ForeignKey("subjects.id"), nullable=True)

    # nombre del ramo (permite horario docente sin estar atado a malla)
    subject_name = Column(String, nullable=False)

    institution = Column(String, nullable=False)
    location = Column(String, nullable=False)

    # 1=Lun ... 7=Dom
    day_of_week = Column(Integer, nullable=False)

    start_time = Column(Time, nullable=False)
    end_time = Column(Time, nullable=False)

    notes = Column(Text, nullable=True)
