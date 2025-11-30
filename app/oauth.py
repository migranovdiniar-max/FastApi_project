from jose import JWSError, jwt
from datetime import datetime, timedelta
from . import schemas
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer

oath2_scheme = OAuth2PasswordBearer(tokenUrl='login')

SECRETE_KEY = "edeafc88c361b492f8908fd7aeb17f9a849551ffd33ec9dc3c4a7bec86a6febe"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRETE_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def verify_access_token(token: str, credentials_exception):
    try: 
        payload = jwt.decode(token, SECRETE_KEY, algorithms=ALGORITHM)

        id: str = payload.get("user_id")

        if id is None:
            raise credentials_exception
        token_data = schemas.TokenData(id=id)
    except JWSError:
        raise credentials_exception
    

def get_current_user(token: str = Depends(oath2_scheme)):
    creadentials_exception = HTTPException(status_code=
                                           status.HTTP_401_UNAUTHORIZED,
                                           detail=
                                           "Could not validate credentials",
                                           headers={"WWW-Authenticate": "Bearer"})    
    return verify_access_token(token, creadentials_exception)