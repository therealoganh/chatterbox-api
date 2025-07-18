from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
  """Hashes a password"""
  return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
  """Verifies a password against a hashed password"""
  return pwd_context.verify(plain, hashed)
