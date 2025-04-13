import fastapi
from fastapi import FastAPI, status, Depends, HTTPException, Header
from typing import Annotated, Optional
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
import auth
from auth import get_current_user
import pg
from superbase import get_db_connection

app = FastAPI()
app.include_router(auth.router)
app.include_router(pg.router)

db_dependancy = Annotated[object, Depends(get_db_connection)]
user_dependancy = Annotated[dict, Depends(get_current_user)]



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/test")
def deployed():
    return "success"





























