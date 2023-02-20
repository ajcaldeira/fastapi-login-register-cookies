'''
A COOKIE IMPLEMENTATION OF A LOGIN SYSTEM
THE COOKIE IS STORED CLIENT SIDE
'''
import os
import sqlite3
from datetime import datetime, timedelta

from dotenv import load_dotenv
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext

from models.models import LoginForm

load_dotenv()  # take environment variables from .env.
from methods.auth import protected

# The test user in the database has the credentials:
# username: johndoe
# password: secret
# Using secret key: 09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7

# database connection
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30
templates = Jinja2Templates(directory="templates")

# password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI instance
app = FastAPI()

# security object for JWT authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# helper function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# helper function to get a user from the username
def get_user(username: str):
    cursor.execute("SELECT username, password FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if row:
        return {'username': row[0], 'hashed_password': row[1]}
    return None

# helper function to authenticate a user
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user['hashed_password']):
        return False
    return user

# helper function to create a JWT access token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# endpoint to register a new user
@app.post("/register")
async def register(username: str, password: str):
    if get_user(username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = pwd_context.hash(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    return {"message": "User registered"}

# endpoint to authenticate and create a JWT access token
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    response = JSONResponse({"access_token": access_token, "token_type": "bearer"})
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)
    return response

# endpoint to get the current user
@app.get("/me")
@protected # Use this decorator to protect the endpoint (only logged in user can access it)
async def read_users_me(access_token: str = Cookie(None)):
    # Instead of the following 2 lines, I'm using the @protected decorator
    # if access_token is None:
    #     raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return {"username": user['username']}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # If user is logged in, redirect them to /me
    if request.cookies.get('access_token'):
        return RedirectResponse(url='/me')
    return templates.TemplateResponse("login.html", {"request": request})

# endpoint to logout and delete the access token cookie
@app.get("/logout")
async def logout():
    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie(key="access_token")
    return response
