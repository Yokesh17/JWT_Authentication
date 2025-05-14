from fastapi import FastAPI, Depends, HTTPException, APIRouter, File, UploadFile, Form
from fastapi.responses import FileResponse
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import timedelta, datetime, timezone
import os
from pydantic import BaseModel
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from fastapi.responses import StreamingResponse, JSONResponse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from os import urandom
from io import BytesIO


router = APIRouter(prefix='/rapid',tags=['rapid'])

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

SECRET_KEY = '3213d8b8908c6224acad88f034b3a39eb46cdd3d40ae817a26beb930a1870353'
ALGORITHM = 'HS256'

# Generate and store the Fernet key (replace with secure key management in production)
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

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


# @router.post("/encrypt_file")
# async def encrypt_file(file: UploadFile = File(...)):
#     file_data = await file.read()
#     encrypted_data = fernet.encrypt(file_data)

#     return StreamingResponse(
#         BytesIO(encrypted_data),
#         media_type='application/octet-stream',
#         headers={"Content-Disposition": f"attachment; filename=e_{file.filename}"}
#     )

# @router.post("/decrypt_file")
# async def decrypt_file(file: UploadFile = File(...)):
#     try:
#         file_data = await file.read()
#         decrypted_data = fernet.decrypt(file_data)

#         return StreamingResponse(
#             BytesIO(decrypted_data),
#             media_type='application/octet-stream',
#             headers={"Content-Disposition": f"attachment; filename=d_{file.filename}"}
#         )
#     except Exception:
#         return {"error": "Decryption failed. Invalid key or corrupted file."}


# KEY = urandom(32)  # Use a fixed key from env in production
KEY = b'\xb5(\x9a[\xa447^t\xe3"\x93\xba\xffd\xbd\xedTln\xee\xa6\xf0Q\x93\xb3\xe4\xc1\x99C\xf1\x8e'
print(KEY)
CHUNK_SIZE = 1024 * 1024  # 1MB

def get_cipher(iv, key=KEY):
    return Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())

@router.post("/encrypt_file")
async def encrypt_file(file: UploadFile = File(...)):
    try:
        print(KEY)
        CHUNK_SIZE = 64 * 1024  # 64KB chunks for better performance
        
        # Generate encryption components
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(KEY), modes.CTR(iv), backend=default_backend()).encryptor()
        
        # Create output buffer
        output = BytesIO()
        output.write(iv)  # Write IV at the start
        
        # Process file in chunks
        while chunk := await file.read(CHUNK_SIZE):
            encrypted_chunk = cipher.update(chunk)
            output.write(encrypted_chunk)
        
        # Finalize encryption
        output.write(cipher.finalize())
        output.seek(0)
        
        return StreamingResponse(
            output,
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename=e_{file.filename}"}
        )
    except Exception as e:
        return {"error": str(e)}

@router.post("/decrypt_file")
async def decrypt_file(file: UploadFile = File(...)):
    try:
        CHUNK_SIZE = 64 * 1024  # 64KB chunks for better performance
        
        # Read IV first
        iv = await file.read(16)
        cipher = Cipher(algorithms.AES(KEY), modes.CTR(iv), backend=default_backend()).decryptor()
        
        output = BytesIO()
        
        # Process remaining file in chunks
        while chunk := await file.read(CHUNK_SIZE):
            decrypted_chunk = cipher.update(chunk)
            output.write(decrypted_chunk)
        
        # Finalize decryption
        output.write(cipher.finalize())
        output.seek(0)
        
        return StreamingResponse(
            output,
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename=d_{file.filename}"}
        )
    except Exception as e:
        return {"error": str(e)}




# Derive Fernet key from user password + salt
def derive_key(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=50_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

@router.post("/lock")
async def lock_file(file: UploadFile = File(...), password: str = Form(...)):
    file_data = await file.read()

    # Create a salt for key derivation
    salt = os.urandom(16)
    fernet = derive_key(password, salt)

    # Encrypt the file
    encrypted_data = fernet.encrypt(file_data)

    # Prepend salt to encrypted data so it can be used for unlock
    locked_file = salt + encrypted_data

    return StreamingResponse(
        BytesIO(locked_file),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=locked_{file.filename}"}
    )

@router.post("/unlock")
async def unlock_file(file: UploadFile = File(...), password: str = Form(...)):
    file_data = await file.read()
    salt = file_data[:16]
    encrypted_data = file_data[16:]

    try:
        fernet = derive_key(password, salt)
        decrypted_data = fernet.decrypt(encrypted_data)

        return StreamingResponse(
            BytesIO(decrypted_data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=unlocked_{file.filename}"}
        )
    except Exception:
        return JSONResponse(status_code=403, content={"error": "Invalid password or corrupted file."})




