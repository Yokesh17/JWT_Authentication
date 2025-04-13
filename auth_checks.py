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
import re



async def validate_user(p,db):
    user_check = await check_user(p.username,db)
    if user_check['status']=="failure": return user_check

    email_check = await check_email(p.email, db)
    if email_check['status']=='failure': return email_check

    password_check = validate_password(p.password, p.confirm_password)
    if password_check['status']=="failure" : return password_check

    return {'status' : 'success'}



async def check_user(username,db):
    user = await get_data(db, f"SELECT id FROM public.users WHERE username = '{username}'; ")
    if user: return {"status" : "failure", "detail" : "Username already registered"}
    
    return {'status': 'success'}


async def check_email(email,db):
    if is_valid_email(email):
        email = await get_data(db, f"SELECT id FROM public.users WHERE username = '{email}'; ")
        if email: return {"status" : "failure", "detail" : "Email already registered"}
    else:
        return {"status" : "failure" , "message": "Invalid email"}
    return {'status': 'success'}

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password, confirm_password):
    if password!=confirm_password:
        return {"status": "failure", "message": "Password must match the confirm password"}
    if len(password) < 8:
        return {"status": "failure", "message": "Password must be at least 8 characters long."}
    if not re.search(r"[A-Z]", password):
        return {"status": "failure", "message": "Password must contain at least one uppercase letter."}
    if not re.search(r"[a-z]", password):
        return {"status": "failure", "message": "Password must contain at least one lowercase letter."}
    if not re.search(r"\d", password):
        return {"status": "failure", "message": "Password must contain at least one number."}
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return {"status": "failure", "message": "Password must contain at least one special character."}
    
    return {"status": "success"}












