from fastapi import FastAPI, Depends, HTTPException, APIRouter
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import timedelta, datetime, timezone

router = APIRouter(prefix='/rapid',tags=['rapid'])

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

SECRET_KEY = '3213d8b8908c6224acad88f034b3a39eb46cdd3d40ae817a26beb930a1870353'
ALGORITHM = 'HS256'

@router.post('/hash-password')
async def hash_password(password: str):
    try:
        hashed_password = bcrypt_context.hash(password)
        return {
            "status": "success",
            "hashed_password": hashed_password
        }
    except Exception as e:
        return {"status": "error","message": str(e)}

@router.post('/verify-password')
async def verify_password(password: str, hashed_password: str):
    try:
        is_valid = bcrypt_context.verify(password, hashed_password)
        return {
            "status": "success",
            "is_valid": is_valid
        }
    except Exception as e:
        return {"status": "error","message": str(e)}
    
@router.post('/generate-token')
async def generate_token(data : dict, minutes : int):
    try:
        token_expires = timedelta(minutes=minutes)
        token = await create_access_token(data, token_expires)
        return {
            "status": "success",
            "access_token": token,
            "token_type": "bearer",
            "expires_in": str(minutes)
        }
    except Exception as e:
        return {"status": "error","message": str(e)}

@router.post('/decode-token')
async def decode_token(token: str, validate: bool = False):
    try:
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        result = {
            "status": "success",
            "decoded_data": payload
        }
        if validate:
            validation_status = validate_token(payload)
            result.update({'validation_status' : validation_status})
            print(result)
        return result
    except JWTError:
        return {"status": "failure", "message": "invalid or expired token"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    

async def create_access_token(data : dict, expires_delta: timedelta):
    encode = data
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def validate_token(payload: str):
    if token is None:
        return {"status" : "failure", "message" : "Token is missing"}

    # Remove 'Bearer ' prefix if present
    if token.startswith("Bearer "):
        token = token.replace("Bearer ", "")

    try:
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




















