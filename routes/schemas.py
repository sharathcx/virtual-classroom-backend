from pydantic import BaseModel, EmailStr, Field
class UserCreate(BaseModel):
    id: str
    name: str
    email: str
    password: str
    role: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str

class LoginData(BaseModel):
    email: str
    password: str
    
class CSVUserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str = Field(default="")
    role: str = Field(default="USER")