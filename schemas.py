"""
Database Schemas for Soon (Travel Community)

Each Pydantic model maps to a MongoDB collection (lowercased class name).
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

# Core models (validation layer only)

class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, description="Public handle")
    email: EmailStr
    name: Optional[str] = Field(None, description="Display name")
    bio: Optional[str] = Field(None, max_length=280)
    avatar_url: Optional[str] = None
    password: str = Field(..., min_length=6, description="Hashed in DB; plain only for create")

class Post(BaseModel):
    user_id: str = Field(..., description="Owner (ObjectId as string)")
    caption: Optional[str] = Field(None, max_length=2000)
    images: List[str] = Field(default_factory=list)
    location: Optional[str] = None

class Comment(BaseModel):
    post_id: str
    user_id: str
    text: str = Field(..., min_length=1, max_length=1000)

class Like(BaseModel):
    post_id: str
    user_id: str

class Trip(BaseModel):
    host_id: str
    title: str
    description: Optional[str] = None
    cover_image: Optional[str] = None
    location: str
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    capacity: Optional[int] = Field(default=None, ge=1)
    price: Optional[float] = Field(default=None, ge=0)

class TripJoin(BaseModel):
    trip_id: str
    user_id: str
    status: str = Field(default="joined", description="joined|waitlisted|canceled")

class Follow(BaseModel):
    follower_id: str
    following_id: str
