import fastapi
from fastapi import FastAPI, status, Depends, HTTPException, Header
from typing import Annotated, Optional
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
# import auth
# from auth import get_current_user
# import sql
# from sql import get_db_connection
# import test
# import jobs
import rapid

app = FastAPI()
# app.include_router(auth.router)
# app.include_router(sql.router)
# app.include_router(test.router)
# app.include_router(jobs.app)
app.include_router(rapid.router)

# db_dependancy = Annotated[object, Depends(get_db_connection)]
# user_dependancy = Annotated[dict, Depends(get_current_user)]



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
class LimitUploadSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        max_size = 6 * 1024 * 1024  # 6MB
        if request.headers.get("content-length") and int(request.headers["content-length"]) > max_size:
            return JSONResponse(content={"detail": "File too large"}, status_code=413)
        return await call_next(request)

app.add_middleware(LimitUploadSizeMiddleware)


@app.get("/test")
def deployed():
    return "success"