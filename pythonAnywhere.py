import requests
import fastapi
from fastapi import FastAPI, status, Depends, HTTPException, APIRouter


router = APIRouter(prefix='/pa',tags=['PythonAnywhere'])

@router.get('/query')
def call_api(query : str):
    try:
        response = requests.get(f'https://yokesh17.pythonanywhere.com/run_query?query={query}')
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)

        # Convert response to JSON and return it
        return response.json()

    except requests.exceptions.RequestException as e:
        print("API request failed:", e)
        return None
    
@router.get('/update_query')
def call(query : str):
    try:
        response = requests.post(f'https://yokesh17.pythonanywhere.com/insert_user?query={query}')
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)

        # Convert response to JSON and return it
        return response.json()

    except requests.exceptions.RequestException as e:
        print("API request failed:", e)
        return None

# Run it

