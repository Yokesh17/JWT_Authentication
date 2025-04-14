import pymysql
import arrow
from fastapi import APIRouter
import os
from dotenv import load_dotenv
from contextlib import contextmanager
from typing import Generator


load_dotenv()

USER =  os.getenv("SQL_USER")
HOST = os.getenv("SQL_HOST")
PASSWORD = os.getenv("SQL_PASSWORD")
DATABASE = os.getenv("SQL_DATABASE")

router = APIRouter(prefix='/sql', tags=['sql']) 

def nowd():
    return arrow.now('Asia/Kolkata').format('YYYY-MM-DD HH:mm:ss')

# Function to get the database connection
def get_db_connection() -> Generator:
    connection = None
    try:
        connection = pymysql.connect(host=HOST, user=USER, password=PASSWORD, database=DATABASE, cursorclass=pymysql.cursors.DictCursor)
        cursor = connection.cursor()
        yield cursor
    except Exception as e:
        if connection: connection.rollback()
        raise e
    finally:
        if connection:
            cursor.close()
            connection.close()


@contextmanager
def get_cursor():
    """
    Context manager for getting a cursor
    """
    connection = None
    try:
        connection = pymysql.connect(host=HOST, user=USER, password=PASSWORD, database=DATABASE, cursorclass=pymysql.cursors.DictCursor)
        cursor = connection.cursor()
        yield cursor
    except Exception as e:
        if connection:
            connection.rollback()
        raise e
    finally:
        if connection:
            connection.close()

async def get_datas(cursor,query):
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except Exception as e:
        raise e
    
async def get_data(cursor,query):
    try:
        cursor.execute(query)
        return cursor.fetchone()
    except Exception as e:
        raise e

async def execute_query(cursor, query, params=None):
    try:
        cursor.execute(query, params or ())
        return cursor.fetchall()
    except Exception as e:
        raise e

async def update(cursor,query):
    try:
        cursor.execute(query)
        return
    except Exception as e:
        raise e
    
async def return_update(cursor,query):
    try:
        cursor.execute(query)
        return cursor.fetchone()
    except Exception as e:
        raise e





