from jose import jwt
from datetime import datetime, timedelta, UTC
from dotenv import load_dotenv
import os

load_dotenv()

# pull key and algo from env
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if not SECRET_KEY or not ALGORITHM:
    raise ValueError("SECRET_KEY or ALGORITHM not set in environment variables.")


# Create a JWT auth token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt