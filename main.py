import fastapi
from fastapi import FastAPI, status, Depends, HTTPException, Header
from typing import Annotated, Optional
from sqlalchemy.orm import Session
import auth
from auth import get_current_user
import pg
from superbase import get_db_connection

app = FastAPI()
app.include_router(auth.router)
app.include_router(pg.router)

db_dependancy = Annotated[object, Depends(get_db_connection)]
user_dependancy = Annotated[dict, Depends(get_current_user)]

@app.get("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependancy, db: db_dependancy):
    if user is None:
        return {"status" : "failure", "message": "could not validate user"}
    return {'User' : user}

# Example of a protected route that uses the token directly
@app.get("/protected")
async def protected_route(token: Optional[str] = Header(None)):
    result = await auth.validate_token(token)
    if result["status"] == "failure":
        return result
    return {"message": "This is a protected route", "user": result}

@app.get("/test")
def deployed():
    return auth.oauth2_bearer





























