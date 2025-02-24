from database import Base
from sqlalchemy import Column, String, Enum

class User(Base):
    __tablename__ = "user"

    id = Column(String(191), primary_key=True)
    name = Column(String(191), nullable=False)
    email = Column(String(191), unique=True, nullable=False)
    password = Column(String(191), nullable=False)
    role = Column(Enum("STUDENT", "TEACHER", "ADMIN", name="user_role"), nullable=False)