from datetime import timedelta, datetime, timezone
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from superbase import get_db_connection, execute_query, get_data, return_update ,algorithm, secret_key

router = APIRouter(prefix='/auth', tags=['auth'])   

SECRET_KEY = secret_key
ALGORITHM = algorithm

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
# oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

class CreateUserRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None

db_dependancy = Annotated[object, Depends(get_db_connection)]

@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependancy, create_user_request: CreateUserRequest):
    try:
        # Check if user already exists
        user = get_data(db, f"SELECT id FROM public.users WHERE username = '{create_user_request.username}'; ")
        if user:
            return {"status" : "failure", "detail" : "Username already registered"}
        
        # Insert new user
        hashed_password = bcrypt_context.hash(create_user_request.password)
        user_id = return_update(db, f"INSERT INTO public.users (username, password) VALUES ('{create_user_request.username}', '{hashed_password}') RETURNING id")
    
        db.connection.commit()
        
        return {"status": "success","message": "User created successfully", "user_id": user_id['id']}
    except Exception as e:
        return {"status" : "error" , "message" : str(e)}

@router.post('/login',response_model=Token, response_model_exclude_none=True)
async def login_for_access_token(form_data: CreateUserRequest, db: db_dependancy):
    user = authenticate_user(form_data.username, form_data.password, db)
    if user.get("status") == "failure" or user.get("status") == "error":
        return user
    token_expires = timedelta(minutes=100)
    token = create_access_token(user["username"], user["id"], token_expires)

    return {'status' : 'success','message' : 'Login success','access_token': token, 'token_type': 'bearer'}

def authenticate_user(username: str, password: str, db : db_dependancy):
    try:
        user = get_data(db, f"SELECT id, username, password FROM users WHERE username = '{username}'; ")
        if not user:
            return {"status" : "failure" , "message" : "user not found"}
        if not bcrypt_context.verify(password, user["password"]):
            return {"status" : "failure", "message" : "invalid credentials"} 
        return user
    except Exception as e:
        return {"status" : "error", "message" : str(e)}

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Optional[str] = Header(None)):
    result = await validate_token(token)
    return result
    

# New function to validate token passed directly
async def validate_token(token: Optional[str] = Header(None)):
    if token is None:
        return {"status" : "failure", "message" : "Token is missing"}
    
    # Remove 'Bearer ' prefix if present
    if token.startswith("Bearer "):
        token = token.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        expire_time = payload.get('exp')
        if expire_time:
            exp_datetime = datetime.fromtimestamp(expire_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            print(exp_datetime,current_time)
            if current_time >= exp_datetime:
                return {"status": "failure", "message": "Token has expired"}
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            return {"status": "failure", "message": "could not validate user"}
        return {"status": "success", 'username': username, 'id': user_id}
    except JWTError:
        return {"status": "failure", "message": "invalid or expired token"}
    except Exception as e:
        return {"status": "failure", "message": str(e)}


# Working model
@router.get("/secure-token")
def secure_with_token(token: str = Depends(validate_token)):
    return {"message": "Verified!", "your_token": token}
