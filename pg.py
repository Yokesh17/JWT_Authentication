import requests
from fastapi import FastAPI, status, Depends, HTTPException, APIRouter
from superbase import get_db_connection, get_datas

router = APIRouter(prefix='/sp', tags=['Superbase'])

@router.post('/connect')
def run(query : str,db = Depends(get_db_connection)):
    try:
        # query = "select * from public.users"
        query = query
        result1 = get_datas(db, query)
        return result1

    except Exception as e:
        print(e)
        return {"status" : "error", "message" : str(e)}




















