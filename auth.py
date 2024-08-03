from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException, status
from jose import JWTError, jwt
from datetime import datetime, timedelta
from models import hash_password, verify_password, users_collection
from pydantic import BaseModel

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class User(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_user(user: User):
    user_in_db = users_collection.find_one({"username": user.username})
    if user_in_db:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(user.password)
    users_collection.insert_one({"username": user.username, "hashed_password": hashed_password})
    return {"msg": "User created"}


def login(user: User):
    user_in_db = users_collection.find_one({"username": user.username})
    if not user_in_db or not verify_password(user_in_db['hashed_password'], user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data
