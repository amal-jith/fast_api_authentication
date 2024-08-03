from pymongo import MongoClient
from pydantic import BaseModel
import bcrypt

client = MongoClient('mongodb://localhost:27017/')
db = client['fastapi_db']
users_collection = db['users']

class UserInDB(BaseModel):
    username: str
    hashed_password: str

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(stored_password: str, provided_password: str) -> bool:
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))
