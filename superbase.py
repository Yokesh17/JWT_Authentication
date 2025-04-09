import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os
import requests
from fastapi import FastAPI, status, Depends, HTTPException, APIRouter
from typing import Generator
from contextlib import contextmanager

# Load environment variables from .env
load_dotenv()

# Fetch variables from environment
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
secret_key = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM")

def get_db_connection() -> Generator:
    connection = None
    try:
        connection = psycopg2.connect(user=DB_USER,password=DB_PASSWORD,host=DB_HOST,port=DB_PORT,dbname=DB_NAME)
        cursor = connection.cursor(cursor_factory=RealDictCursor)
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
        connection = psycopg2.connect(user=DB_USER,password=DB_PASSWORD,host=DB_HOST,port=DB_PORT,dbname=DB_NAME)
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        yield cursor
    except Exception as e:
        if connection:
            connection.rollback()
        raise e
    finally:
        if connection:
            connection.close()

def get_datas(cursor,query):
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except Exception as e:
        raise e
    
def get_data(cursor,query):
    try:
        cursor.execute(query)
        return cursor.fetchone()
    except Exception as e:
        raise e

def execute_query(cursor, query, params=None):
    try:
        cursor.execute(query, params or ())
        return cursor.fetchall()
    except Exception as e:
        raise e

def update(cursor,query):
    try:
        cursor.execute(query)
        return
    except Exception as e:
        raise e
    
def return_update(cursor,query):
    try:
        cursor.execute(query)
        return cursor.fetchone()
    except Exception as e:
        raise e