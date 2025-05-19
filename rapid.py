from fastapi import FastAPI, Depends, HTTPException, APIRouter, File, UploadFile, Form, BackgroundTasks
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
from PyPDF2 import PdfReader, PdfWriter
import pyminizip
import uuid

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

def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

@router.post("/encrypt_file")
async def encrypt_file(
    file: UploadFile = File(...),
    password: str = Form(...)
):
    try:
        # Generate salt and IV
        salt = os.urandom(16)
        iv = os.urandom(16)  # For AES-CTR

        # Derive key from password
        key = derive_key(password, salt)

        # Create encryptor with AES-CTR
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Create output buffer and write metadata
        output = BytesIO()
        output.write(salt)  # 16 bytes
        output.write(iv)    # 16 bytes

        # Add a verification token (32 bytes of zeros encrypted)
        verification_token = b'\x00' * 32
        encrypted_token = encryptor.update(verification_token)
        output.write(encrypted_token)

        # Process file in chunks
        CHUNK_SIZE = 1024 * 1024  # 1MB chunks
        while chunk := await file.read(CHUNK_SIZE):
            encrypted_chunk = encryptor.update(chunk)
            output.write(encrypted_chunk)

        # Finalize encryption
        output.write(encryptor.finalize())
        output.seek(0)

        return StreamingResponse(
            output,
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename=e_{file.filename}"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"error": f"Encryption failed: {str(e)}", "status": "failure"}
        )

@router.post("/decrypt_file")
async def decrypt_file(
    file: UploadFile = File(...),
    password: str = Form(...)
):
    try:
        # Read metadata first
        salt = await file.read(16)
        iv = await file.read(16)

        # Derive key from password
        key = derive_key(password, salt)

        # Create decryptor
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Verify the password by checking the verification token
        encrypted_token = await file.read(32)
        decrypted_token = decryptor.update(encrypted_token)

        # If password is correct, the token should be all zeros
        if decrypted_token != b'\x00' * 32:
            return JSONResponse(
                status_code=401,
                content={"error": "Incorrect password", "status": "failure"}
            )

        # Create output buffer for the actual file content
        output = BytesIO()

        # Process the rest of the file in chunks
        CHUNK_SIZE = 1024 * 1024  # 1MB chunks
        while chunk := await file.read(CHUNK_SIZE):
            decrypted_chunk = decryptor.update(chunk)
            output.write(decrypted_chunk)

        # Finalize decryption
        output.write(decryptor.finalize())
        output.seek(0)

        return StreamingResponse(
            output,
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename=d_{file.filename}"}
        )
    except ValueError as ve:
        # This might happen if the file is too small or not properly formatted
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid file format", "status": "failure"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"error": f"Decryption failed: {str(e)}", "status": "failure"}
        )

TEMP_DIR = "temp"
os.makedirs(TEMP_DIR, exist_ok=True)


def remove_files(*paths):
    for path in paths:
        if os.path.exists(path):
            os.remove(path)


@router.post("/lock-pdf")
async def lock_pdf(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    password: str = Form(...)
):
    # Save uploaded PDF
    temp_input_path = os.path.join(TEMP_DIR, f"{uuid.uuid4()}_{file.filename}")
    with open(temp_input_path, "wb") as f:
        f.write(await file.read())

    # Encrypt PDF
    reader = PdfReader(temp_input_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(password)

    output_path = temp_input_path.replace(".pdf", "_l.pdf")
    with open(output_path, "wb") as f:
        writer.write(f)

    # Schedule cleanup
    background_tasks.add_task(remove_files, temp_input_path, output_path)

    return FileResponse(output_path, filename="locked.pdf", media_type="application/pdf")


@router.post("/lock-as-zip")
async def lock_any_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    password: str = Form(...)
):
    # Save uploaded file
    temp_input_path = os.path.join(TEMP_DIR, f"{uuid.uuid4()}_{file.filename}")
    with open(temp_input_path, "wb") as f:
        f.write(await file.read())

    # Password-protected ZIP
    zip_path = temp_input_path + ".zip"
    pyminizip.compress(temp_input_path, None, zip_path, password, 5)

    # Schedule cleanup
    background_tasks.add_task(remove_files, temp_input_path, zip_path)

    return FileResponse(zip_path, filename="protected.zip", media_type="application/zip")


