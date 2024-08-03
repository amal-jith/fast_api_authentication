

from fastapi import FastAPI, Depends, HTTPException
from pymongo import MongoClient
from pymongo.collection import Collection
from pydantic import BaseModel
from typing import Optional
import auth

app = FastAPI()

# MongoDB connection URI
MONGO_URI = "mongodb://localhost:27017"

# Create a MongoDB client
client = MongoClient(MONGO_URI)

# Select the database
db = client["fast_api_auth"]

# Define a collection
users_collection: Collection = db["users"]

class User(BaseModel):
    username: str
    password: str

@app.post("/create_user/")
async def create_user(user: User):
    return await auth.create_user(user)

@app.post("/login/")
async def login(user: User):
    return await auth.login(user)

@app.get("/protected/")
async def protected_route(token: str = Depends(auth.oauth2_scheme)):
    return {"message": "This is a protected route", "token": token}