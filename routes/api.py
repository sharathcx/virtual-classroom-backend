from fastapi import Depends, File, HTTPException, UploadFile, status, Request, Response, APIRouter
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
from routes.models import User
from routes.schemas import LoginData, UserCreate, UserResponse, CSVUserCreate
from database import SessionLocal, engine, Base
import csv
import io
import uuid

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return user

def get_current_admin(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    print(token)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.role != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    return user

# Routes
@auth_router.post("/signup", response_model=UserResponse)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    user.password = pwd_context.hash(user.password)
    new_user = User(**user.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@auth_router.post("/login")
def login(response: Response, login_data: LoginData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not pwd_context.verify(login_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.id, "role": user.role})

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevents JavaScript access
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=False,  # Change to False for local development
        samesite="lax",  # Change to "None" if frontend and backend have different origins
    )
   
    return {"message": "Login successful"}

@auth_router.post("/signup/csv", response_model=list[UserResponse])
async def signup_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Read the CSV file
    contents = await file.read()
    file_stream = io.StringIO(contents.decode("utf-8"))
    csv_reader = csv.DictReader(file_stream)

    # List to store created users
    created_users = []

    # Iterate through each row in the CSV
    for row in csv_reader:
        try:
            # Validate the row against the CSVUserCreate model
            user_data = CSVUserCreate(**row)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid data in CSV: {str(e)}",
            )

        # Check if the user already exists
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email {user_data.email} already registered",
            )

        # Hash the password
        hashed_password = pwd_context.hash(user_data.password)

        # Create a new user with a random UUID
        new_user = User(
            id=str(uuid.uuid4()),
            email=user_data.email,
            password=hashed_password,
            name=user_data.name,
            role=user_data.role,
        )

        # Add the user to the database
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Add the created user to the response list
        created_users.append(new_user)

    return created_users

@auth_router.get("/profile", response_model=UserResponse)
def profile(current_user: User = Depends(get_current_user)):
    return current_user

@auth_router.get("/admin/profile", response_model=UserResponse)
def admin_profile(request: Request, current_user: User = Depends(get_current_admin)): 
    return current_user

# Logout endpoint
@auth_router.post("/logout")
def logout(response: Response):
    # Clear the access_token and user_role cookies
    response.delete_cookie("access_token")
    response.delete_cookie("user_role")
    return {"message": "Logged out successfully"}

# Clear database endpoint (for testing purposes)
@auth_router.delete("/clear-database")
def clear_database(db: Session = Depends(get_db)):
    try:
        # Delete all users from the database
        db.query(User).delete()
        db.commit()
        return {"message": "All users deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear database: {str(e)}",
        )

# New endpoint to fetch all users
@auth_router.get("/users", response_model=list[UserResponse])
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users

# Initialize DB
Base.metadata.create_all(bind=engine)