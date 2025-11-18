import os
import hmac
import base64
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db

app = FastAPI(title="Soon API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------- Utilities ----------------------
SECRET = os.getenv("AUTH_SECRET", "change-me")

def oid() -> str:
    return str(ObjectId())


def now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    salt_bytes = os.urandom(16) if salt is None else base64.b64decode(salt)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 100_000)
    return {
        "salt": base64.b64encode(salt_bytes).decode(),
        "hash": base64.b64encode(hashed).decode(),
    }


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    calc = hash_password(password, salt)
    return hmac.compare_digest(calc["hash"], stored_hash)


def sign_token(payload: Dict[str, Any]) -> str:
    data = base64.urlsafe_b64encode(str(payload).encode()).decode()
    sig = hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"


def verify_token(token: str) -> Dict[str, Any]:
    try:
        data, sig = token.split(".")
        expected = hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("Bad signature")
        payload_str = base64.urlsafe_b64decode(data.encode()).decode()
        # eval-like safe parsing; payload is dict string. We'll parse simply.
        payload = {}
        for item in payload_str.strip("{} ").split(","):
            if not item.strip():
                continue
            k, v = item.split(":", 1)
            payload[k.strip().strip("'\"")] = v.strip().strip("'\"")
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")


class AuthedUser(BaseModel):
    id: str
    username: str


def get_current_user(authorization: Optional[str] = Header(None)) -> AuthedUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    payload = verify_token(token)
    uid = payload.get("user_id")
    username = payload.get("username", "")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return AuthedUser(id=uid, username=username)

# ---------------------- Models ----------------------
class SignupRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    name: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    token: str
    user_id: str
    username: str

class PostCreate(BaseModel):
    caption: Optional[str] = None
    images: List[str] = []
    location: Optional[str] = None

class CommentCreate(BaseModel):
    text: str

class TripCreate(BaseModel):
    title: str
    description: Optional[str] = None
    cover_image: Optional[str] = None
    location: str
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    capacity: Optional[int] = None
    price: Optional[float] = None

# ---------------------- Auth ----------------------
@app.post("/auth/signup", response_model=TokenResponse)
def signup(req: SignupRequest):
    if db["user"].find_one({"email": req.email}):
        raise HTTPException(400, "Email already registered")
    if db["user"].find_one({"username": req.username}):
        raise HTTPException(400, "Username taken")
    creds = hash_password(req.password)
    user = {
        "_id": oid(),
        "username": req.username,
        "email": req.email,
        "name": req.name or req.username,
        "bio": "",
        "avatar_url": "",
        "password_hash": creds["hash"],
        "password_salt": creds["salt"],
        "created_at": now(),
        "updated_at": now(),
    }
    db["user"].insert_one(user)
    token = sign_token({"user_id": user["_id"], "username": user["username"]})
    return TokenResponse(token=token, user_id=user["_id"], username=user["username"])


@app.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email})
    if not user or not verify_password(req.password, user["password_salt"], user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    token = sign_token({"user_id": user["_id"], "username": user["username"]})
    return TokenResponse(token=token, user_id=user["_id"], username=user["username"])

# ---------------------- Feed & Posts ----------------------
@app.post("/posts", status_code=201)
def create_post(data: PostCreate, user: AuthedUser = Depends(get_current_user)):
    post = {
        "_id": oid(),
        "user_id": user.id,
        "caption": data.caption,
        "images": data.images or [],
        "location": data.location,
        "created_at": now(),
        "updated_at": now(),
    }
    db["post"].insert_one(post)
    return post

@app.get("/feed")
def get_feed(limit: int = 10, cursor: Optional[str] = None):
    query: Dict[str, Any] = {}
    sort = [("created_at", -1), ("_id", -1)]
    if cursor:
        # cursor is created_at|_id concatenated; for simplicity, use _id only
        query["_id"] = {"$lt": cursor}
    items = list(db["post"].find(query).sort(sort).limit(min(limit, 50)))
    for p in items:
        u = db["user"].find_one({"_id": p["user_id"]}, {"username": 1, "avatar_url": 1})
        p["user"] = {"username": u.get("username") if u else "unknown", "avatar_url": (u or {}).get("avatar_url", "")}
        p["likes"] = db["like"].count_documents({"post_id": p["_id"]})
        p["comments_count"] = db["comment"].count_documents({"post_id": p["_id"]})
    next_cursor = items[-1]["_id"] if items else None
    return {"items": items, "nextCursor": next_cursor}

@app.post("/posts/{post_id}/like")
def toggle_like(post_id: str, user: AuthedUser = Depends(get_current_user)):
    existing = db["like"].find_one({"post_id": post_id, "user_id": user.id})
    if existing:
        db["like"].delete_one({"_id": existing["_id"]})
        liked = False
    else:
        db["like"].insert_one({"_id": oid(), "post_id": post_id, "user_id": user.id, "created_at": now()})
        liked = True
    count = db["like"].count_documents({"post_id": post_id})
    return {"liked": liked, "count": count}

@app.get("/posts/{post_id}/comments")
def list_comments(post_id: str, limit: int = 50):
    comments = list(db["comment"].find({"post_id": post_id}).sort([("created_at", 1)]).limit(min(limit, 100)))
    for c in comments:
        u = db["user"].find_one({"_id": c["user_id"]}, {"username": 1, "avatar_url": 1})
        c["user"] = {"username": u.get("username") if u else "unknown", "avatar_url": (u or {}).get("avatar_url", "")}
    return comments

@app.post("/posts/{post_id}/comments")
def add_comment(post_id: str, data: CommentCreate, user: AuthedUser = Depends(get_current_user)):
    if not db["post"].find_one({"_id": post_id}):
        raise HTTPException(404, "Post not found")
    comment = {"_id": oid(), "post_id": post_id, "user_id": user.id, "text": data.text, "created_at": now()}
    db["comment"].insert_one(comment)
    return comment

# ---------------------- Users & Follow ----------------------
@app.get("/users/{user_id}")
def get_user_profile(user_id: str, viewer: Optional[AuthedUser] = Depends(get_current_user)):
    u = db["user"].find_one({"_id": user_id}, {"password_hash": 0, "password_salt": 0})
    if not u:
        raise HTTPException(404, "User not found")
    stats = {
        "posts": db["post"].count_documents({"user_id": user_id}),
        "followers": db["follow"].count_documents({"following_id": user_id}),
        "following": db["follow"].count_documents({"follower_id": user_id}),
        "hosted_trips": db["trip"].count_documents({"host_id": user_id}),
        "joined_trips": db["tripjoin"].count_documents({"user_id": user_id, "status": "joined"}),
    }
    is_following = False
    if viewer:
        is_following = db["follow"].find_one({"follower_id": viewer.id, "following_id": user_id}) is not None
    return {"user": u, "stats": stats, "is_following": is_following}

@app.get("/users/{user_id}/posts")
def user_posts(user_id: str, limit: int = 30):
    posts = list(db["post"].find({"user_id": user_id}).sort([("created_at", -1)]).limit(min(limit, 100)))
    return posts

@app.get("/users/{user_id}/trips")
def user_trips(user_id: str, role: Optional[str] = None):
    hosted = list(db["trip"].find({"host_id": user_id}).sort([("start_date", 1)]))
    joined_ids = [t["trip_id"] for t in db["tripjoin"].find({"user_id": user_id, "status": "joined"})]
    joined = list(db["trip"].find({"_id": {"$in": joined_ids}})) if joined_ids else []
    if role == "host":
        return hosted
    if role == "joined":
        return joined
    return {"hosted": hosted, "joined": joined}

@app.post("/follow/{target_id}")
def follow_user(target_id: str, user: AuthedUser = Depends(get_current_user)):
    if target_id == user.id:
        raise HTTPException(400, "Cannot follow yourself")
    if not db["user"].find_one({"_id": target_id}):
        raise HTTPException(404, "User not found")
    if db["follow"].find_one({"follower_id": user.id, "following_id": target_id}):
        return {"following": True}
    db["follow"].insert_one({"_id": oid(), "follower_id": user.id, "following_id": target_id, "created_at": now()})
    return {"following": True}

@app.delete("/follow/{target_id}")
def unfollow_user(target_id: str, user: AuthedUser = Depends(get_current_user)):
    db["follow"].delete_many({"follower_id": user.id, "following_id": target_id})
    return {"following": False}

# ---------------------- Trips ----------------------
@app.post("/trips", status_code=201)
def create_trip(data: TripCreate, user: AuthedUser = Depends(get_current_user)):
    trip = {
        "_id": oid(),
        "host_id": user.id,
        "title": data.title,
        "description": data.description,
        "cover_image": data.cover_image,
        "location": data.location,
        "start_date": data.start_date,
        "end_date": data.end_date,
        "capacity": data.capacity,
        "price": data.price,
        "created_at": now(),
        "updated_at": now(),
    }
    db["trip"].insert_one(trip)
    return trip

@app.get("/trips/{trip_id}")
def get_trip(trip_id: str, viewer: Optional[AuthedUser] = Depends(get_current_user)):
    trip = db["trip"].find_one({"_id": trip_id})
    if not trip:
        raise HTTPException(404, "Trip not found")
    host = db["user"].find_one({"_id": trip["host_id"]}, {"username": 1, "avatar_url": 1})
    trip["host"] = {"username": host.get("username") if host else "unknown", "avatar_url": (host or {}).get("avatar_url", "")}
    trip["joined_count"] = db["tripjoin"].count_documents({"trip_id": trip_id, "status": "joined"})
    is_joined = False
    if viewer:
        is_joined = db["tripjoin"].find_one({"trip_id": trip_id, "user_id": viewer.id, "status": "joined"}) is not None
    trip["is_joined"] = is_joined
    return trip

@app.post("/trips/{trip_id}/join")
def join_trip(trip_id: str, user: AuthedUser = Depends(get_current_user)):
    trip = db["trip"].find_one({"_id": trip_id})
    if not trip:
        raise HTTPException(404, "Trip not found")
    if trip["host_id"] == user.id:
        raise HTTPException(400, "Hosts are already part of their trip")
    joined_count = db["tripjoin"].count_documents({"trip_id": trip_id, "status": "joined"})
    if trip.get("capacity") and joined_count >= trip["capacity"]:
        status = "waitlisted"
    else:
        status = "joined"
    existing = db["tripjoin"].find_one({"trip_id": trip_id, "user_id": user.id})
    if existing:
        db["tripjoin"].update_one({"_id": existing["_id"]}, {"$set": {"status": status, "updated_at": now()}})
    else:
        db["tripjoin"].insert_one({"_id": oid(), "trip_id": trip_id, "user_id": user.id, "status": status, "created_at": now(), "updated_at": now()})
    return {"status": status}

# ---------------------- Health/Test ----------------------
@app.get("/")
def read_root():
    return {"message": "Soon API is running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = getattr(db, 'name', '✅ Connected')
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
