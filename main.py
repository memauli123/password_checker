from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import string
import math
import re
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to the Password Strength Checker API!"}

# Allow frontend to access backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PasswordRequest(BaseModel):
    password: str

def calculate_entropy(password: str) -> float:
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)
    
    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
    return entropy

def check_strength(password: str) -> str:
    length_score = len(password) >= 8
    upper_lower = bool(re.search(r"[a-z]", password) and re.search(r"[A-Z]", password))
    number = bool(re.search(r"\d", password))
    special_char = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    entropy = calculate_entropy(password)
    
    if length_score and upper_lower and number and special_char and entropy > 60:
        return "Strong"
    elif length_score and (upper_lower or number or special_char) and entropy > 40:
        return "Moderate"
    else:
        return "Weak"

@app.post("/check_password")
def check_password(password_request: PasswordRequest):
    password = password_request.password
    if not password:
        raise HTTPException(status_code=400, detail="Password cannot be empty")
    
    strength = check_strength(password)
    return {"password": password, "strength": strength}
