# main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from models import User,  Blog
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from database import SessionLocal, engine , Base
import models
import database
# Configuration

SECRET_KEY = "y5439567d8b64fb4b3a84b2ab8a7870aecd48b5c2d1708a49205e20f998058df2"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Create FastAPI app
app = FastAPI()

models.Base.metadata.create_all(bind =engine)

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

# Pydantic models
class UserCreate(BaseModel):
    name: str
    email: str
    phone_number: str
    password : str

class UserInDB(UserCreate):
    id: int
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str = None

class BlogBase(BaseModel):
    title: str
    content: str

class BlogCreate(BlogBase):
    pass

class BlogUpdate(BlogBase):
    pass

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Authentication and token generation
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        token_data = TokenData(email=email)
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return token_data

# API routes
@app.post("/register/")
async def register(user: UserCreate, db : session = Depends(get_db)):
    print(user,"String")
    fake_hashed_password = user.password + "notreallyhashed"
    db_user = models.User(email=user.email, password = fake_hashed_password)
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except Exception as e: 
        print (e)
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await database.fetch_one(User.__table__.select().where(User.email == form_data.username))
    if user is None or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": form_data.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=User)
async def create_user(user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    query = User.__table__.insert().values(
        name=user.name,
        email=user.email,
        phone_number=user.phone_number,
        hashed_password=hashed_password,
    )
    user_id = await database.execute(query)
    return {**user.dict(), "id": user_id}

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/blogs/", response_model=Blog)
async def create_blog(blog: BlogCreate, current_user: User = Depends(get_current_user)):
    query = Blog.__table__.insert().values(
        title=blog.title,
        content=blog.content,
    )
    blog_id = await database.execute(query)
    return {**blog.dict(), "id": blog_id}



@app.put("/blogs/{blog_id}/", response_model=Blog)
async def update_blog(blog_id: int, blog: BlogUpdate, current_user: User = Depends(get_current_user)):
    query = Blog.__table__.update().where(Blog.id == blog_id).values(
        title=blog.title,
        content=blog.content,
    )
    await database.execute(query)
    return {**blog.dict(), "id": blog_id}



@app.delete("/blogs/{blog_id}/", response_model=Blog)
async def delete_blog(blog_id: int, current_user: User = Depends(get_current_user)):
    query = Blog.__table__.delete().where(Blog.id == blog_id)
    await database.execute(query)
    return {"message": "Blog deleted successfully"}


