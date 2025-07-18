# ----------------------
# LOCAL MODULES
# ----------------------
from auth import create_access_token, SECRET_KEY, ALGORITHM
from utils import hash_password, verify_password
from models import Message, MessageRead, MessageUpdate, User, UserCreate, UserLogin, UserPublic, UserUpdate

# ----------------------
# EXTERNAL MODULES
# ----------------------

# from contextlib import asynccontextmanager
from jose import JWTError, jwt
import os
from dotenv import load_dotenv

load_dotenv()
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, SQLModel, create_engine, select

# ----------------------
# DATABASE SETUP
# ----------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login-form")

raw_path = os.getenv("DATABASE_URL", "./chatterbox.db")

# Ensure proper URL format
if not raw_path.startswith("sqlite:///"):
    db_path = raw_path
    raw_path = f"sqlite:///{raw_path}"
else:
    db_path = raw_path.replace("sqlite:///", "")

# ✅ Ensure the directory exists
os.makedirs(os.path.dirname(db_path), exist_ok=True)

engine = create_engine(raw_path, echo=True)


def create_db():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


# ----------------------
# HELPER FUNCTIONS
# ----------------------


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    """Decode JWT and return user"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=401,
                                detail="Token missing user ID")

        user_id = int(sub)

    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


# ----------------------
# APP STARTUP
# ----------------------


async def lifespan(app: FastAPI):
    create_db()
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Temporary: Root route
@app.get("/")
def root():
    return {"message": "Chatterbox backend is live!"}


# ----------------------
# MESSAGE ROUTES
# ----------------------


# Messages route: Create a new message
@app.post("/messages")
def create_message(content: str, session: Annotated[Session,
                                                    Depends(get_session)],
                   current_user: Annotated[User,
                                           Depends(get_current_user)]):

    # type check
    if current_user.id is None:
        raise HTTPException(status_code=500,
                            detail="User ID missing from token")

    # Create and save message
    message = Message(content=content, user_id=current_user.id)
    session.add(message)
    session.commit()
    session.refresh(message)

    return message


# Messages route: List all messages
@app.get("/messages", response_model=List[MessageRead])
def list_messages(session: Annotated[Session, Depends(get_session)]):
    statement = select(Message)
    messages = session.exec(statement).all()

    # Check for messages
    if not messages:
        return []

    return messages


# Messages route: List messages by user_id
@app.get("/users/{user_id}/messages", response_model=List[MessageRead])
def get_messages_by_user(user_id: int,
                         session: Annotated[Session,
                                            Depends(get_session)]):

    # Check for user
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    statement = select(Message).where(Message.user_id == user_id)
    messages = session.exec(statement).all()

    if not messages:
        return []

    return messages


# Update a message
@app.patch("/messages/{message_id}", response_model=Message)
def update_message(message_id: int, update: MessageUpdate,
                   session: Annotated[Session, Depends(get_session)],
                   current_user: Annotated[User,
                                           Depends(get_current_user)]):

    # Check that message exists
    message = session.get(Message, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Only owner can update
    if not message.user_id == current_user.id:
        raise HTTPException(status_code=403,
                            detail="Not authorized to update this message")

    if update.content is not None:
        message.content = update.content

    session.add(message)
    session.commit()
    session.refresh(message)

    return message


# Delete a message
@app.delete("/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_message(message_id: int, session: Annotated[Session,
                                                       Depends(get_session)],
                   current_user: Annotated[User,
                                           Depends(get_current_user)]):

    # Check if message exists
    message = session.get(Message, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Only owner can delete
    if not message.user_id == current_user.id:
        raise HTTPException(status_code=403,
                            detail="Not authorized to update this message")

    session.delete(message)
    session.commit()

    return


# ----------------------
# USER ROUTES
# ----------------------


#  User route: Create a new user
@app.post("/users")
def create_user(user: UserCreate, session: Annotated[Session,
                                                     Depends(get_session)]):

    # Check if user exists
    statement = select(User).where(User.username == user.username)
    if session.exec(statement).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_pwd = hash_password(user.password)

    # Create and save new user
    new_user = User(username=user.username, hashed_password=hashed_pwd)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    # Return new user
    return new_user


# Get users
@app.get("/users/{user_id}", response_model=UserPublic)
def get_user(user_id: int, session: Annotated[Session, Depends(get_session)]):

    # Check if user exists
    user = session.get(User, user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


# Update user
@app.patch("/users/{user_id}", response_model=UserPublic)
def update_user(user_id: int, update: UserUpdate,
                session: Annotated[Session, Depends(get_session)],
                current_user: Annotated[User, Depends(get_current_user)]):

    # Auth check
    if current_user.id != user_id:
        raise HTTPException(status_code=403,
                            detail="Not authorized to update this user")

    # Check if user exists
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if update.username is not None:
        user.username = update.username
    if update.password is not None:
        hashed_pwd = hash_password(update.password)
        user.hashed_password = hashed_pwd

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


# Delete user & their messages
@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, session: Annotated[Session,
                                                 Depends(get_session)],
                current_user: Annotated[User, Depends(get_current_user)]):

    if user_id != current_user.id:
        raise HTTPException(status_code=403,
                            detail="Not authorized to delete this user")

    # Delete all messages by the user
    statement = select(Message).where(Message.user_id == current_user.id)
    messages = session.exec(statement).all()
    for msg in messages:
        session.delete(msg)

    session.delete(current_user)
    session.commit()

    return


# User login
@app.post("/login")
def login_user(user: UserLogin, session: Annotated[Session,
                                                   Depends(get_session)]):
    """JSON-Based login"""
    statement = select(User).where(User.username == user.username)
    found_user = session.exec(statement).first()

    if not found_user or not verify_password(user.password,
                                             found_user.hashed_password):
        raise HTTPException(status_code=404, detail="Invalid credentials")

    # create access token
    access_token = create_access_token(data={"sub": str(found_user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


# Login for Testing
@app.post("/login-form")
def login_form(form_data: Annotated[OAuth2PasswordRequestForm,
                                    Depends()],
               session: Annotated[Session, Depends(get_session)]):
    """Form-based login for JWT auth testing"""
    statement = select(User).where(User.username == form_data.username)
    found_user = session.exec(statement).first()

    if not found_user or not verify_password(form_data.password,
                                             found_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # create access token
    access_token = create_access_token(data={"sub": str(found_user.id)})
    return {"access_token": access_token, "token_type": "bearer"}
