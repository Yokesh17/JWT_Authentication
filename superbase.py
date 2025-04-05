import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os
import requests
from fastapi import FastAPI, status, Depends, HTTPException, APIRouter
from typing import Generator

# Load environment variables from .env
load_dotenv()

# Fetch variables from environment
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

def get_db_connection() -> Generator:
    connection = None
    try:
        connection = psycopg2.connect(user=DB_USER,password=DB_PASSWORD,host=DB_HOST,port=DB_PORT,dbname=DB_NAME)
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        yield cursor
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_datas(cursor,query):
    cursor.execute(query)
    return cursor.fetchall()

