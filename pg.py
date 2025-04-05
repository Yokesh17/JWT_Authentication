import requests
from fastapi import FastAPI, status, Depends, HTTPException, APIRouter
from superbase import get_db_connection, get_datas

router = APIRouter(prefix='/sp', tags=['Superbase'])

@router.get('/connect')
def run(db = Depends(get_db_connection)):
    try:
        query = "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE';"
        result1 = get_datas(db, query)
        print("Result2: ", result1[0])
        # Close the cursor
        return result1

    except Exception as e:
        print(e)
        return {"status" : "error", "message" : str(e)}




















