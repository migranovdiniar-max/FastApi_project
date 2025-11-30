from jose import JWTError, jwt
from datetime import datetime, timedelta
from . import schemas, database, models
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')

SECRETE_KEY = "edeafc88c361b492f8908fd7aeb17f9a849551ffd33ec9dc3c4a7bec86a6febe"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRETE_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def verify_access_token(token: str, credentials_exception):
    try: 
        payload = jwt.decode(token, SECRETE_KEY, algorithms=[ALGORITHM])

        user_id: str = payload.get("user_id")

        if user_id is None:
            raise credentials_exception
        token_data = schemas.TokenData(id=user_id)
    except JWTError:
        raise credentials_exception
    
    return token_data
    

def get_current_user(token: str = Depends(oauth2_scheme), db: Session  = Depends(database.get_db)):
    creadentials_exception = HTTPException(status_code=
                                           status.HTTP_401_UNAUTHORIZED,
                                           detail=
                                           "Could not validate credentials",
                                           headers={"WWW-Authenticate": "Bearer"})  
    token = verify_access_token(token, creadentials_exception)

    user = db.query(models.User).filter(models.User.id == token.id).first()

    return user