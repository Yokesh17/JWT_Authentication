from fastapi import FastAPI, Depends, HTTPException, APIRouter
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import timedelta, datetime, timezone
import os
from pydantic import BaseModel
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import base64

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
async def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        result = {
            "status": "success",
            "decoded_data": payload
        }
    except JWTError:
        return {"status": "failure", "message": "invalid or expired token"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    

async def create_access_token(data : dict, expires_delta: timedelta):
    encode = data
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

class EncryptRequest(BaseModel):
    data: str

class DecryptRequest(BaseModel):
    encrypted_data: str
    key: str

# Encrypt endpoint
@router.post("/encrypt")
def encrypt(req: EncryptRequest):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, req.data.encode(), None)

    combined = nonce + ciphertext  # concatenate nonce with ciphertext
    return {
        "encrypted_data": base64.b64encode(combined).decode(),
        "key": base64.b64encode(key).decode()
    }

# Decrypt endpoint
@router.post("/decrypt")
def decrypt(req: DecryptRequest):
    try:
        key = base64.b64decode(req.key)
        combined = base64.b64decode(req.encrypted_data)

        nonce = combined[:12]
        ciphertext = combined[12:]

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return {"data": plaintext.decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed: " + str(e))
















