from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from pydantic.main import BaseModel

#--------------------
# User Models
#--------------------

class User(SQLModel, table=True):
  id: Optional[int] = Field(default=None, primary_key=True)
  username: str
  hashed_password: str
  messages: List["Message"] = Relationship(back_populates="user")


class UserCreate(BaseModel):
  username: str
  password: str


class UserUpdate(BaseModel):
  username: Optional[str] = None
  password: Optional[str] = None


class UserLogin(BaseModel):
  username: str
  password: str

class UserPublic(BaseModel):
  id: int
  username: str

#--------------------
# Message Models
#--------------------

class Message(SQLModel, table=True):
  id: Optional[int] = Field(default=None, primary_key=True)
  content: str
  user_id: int = Field(foreign_key="user.id")

  user: Optional["User"] = Relationship(back_populates="messages")


class MessageUpdate(BaseModel):
  content: Optional[str] = None

class MessageRead(BaseModel):
  id: int
  content: str
  user_id: int