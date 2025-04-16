from fastapi import APIRouter, Depends, HTTPException, Header
from sql import get_datas, get_db_connection
from typing import Annotated, Optional

router = APIRouter(tags=['test'])
db_dependancy = Annotated[object, Depends(get_db_connection)]

@router.get("/run_query")
async def run_query(query : str, db : db_dependancy):
    try:
        user = await get_datas(db, query)
        if not user:
            return {"status" : "Success" , "message" : "No Data Found"}
        return user
    except Exception as e:
        return {"status" : "error", "message" : str(e)}




