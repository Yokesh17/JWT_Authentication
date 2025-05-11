import random
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, Query, APIRouter
import pandas as pd
from jobspy import scrape_jobs
import numpy as np

app = APIRouter(prefix='/jobs', tags=['jobs'])

# Scraping proxies from a free proxy list
def scrape_proxies():
    try:
        url = "https://free-proxy-list.net/"
        response = requests.get(url)
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch page: {response.status_code}")
        
        soup = BeautifulSoup(response.content, "lxml")
        table = soup.find("table")
        
        if not table:
            raise Exception("Proxy table not found in the page. The website structure may have changed.")
        
        proxies = []
        for row in table.tbody.find_all("tr"):
            cols = row.find_all("td")
            if cols[6].text.strip() == "yes":  # HTTPS proxies only
                proxy = f"{cols[0].text.strip()}:{cols[1].text.strip()}"
                proxies.append(proxy)
        return proxies
    except Exception as e:
        print(f"Error scraping proxies: {e}")
        return {'status' : 'error', 'message': str(e)}

# Validate if the proxy works by testing with httpbin
def validate_proxy(proxy):
    """Test if the proxy works by making a request to httpbin.org/ip."""
    try:
        test_url = "http://httpbin.org/ip"
        proxies = {
            "http": f"http://{proxy}",
            "https": f"http://{proxy}",
        }
        response = requests.get(test_url, proxies=proxies, timeout=5)
        if response.status_code == 200:
            print(f"Working proxy: {proxy}")
            return True
    except Exception as e:
        print({"status" : 'error', 'message': str(e)})
        pass
    return False

# Fetch jobs using a working proxy
def get_jobs(search_term: str, location: str, results_wanted: int, proxy: str):
    try:
        jobs = []
        proxies = {
            "http": f"http://{proxy}",
            "https": f"http://{proxy}",
        }
        #, "linkedin"
        sites = ["google"]
        # sites= ["indeed", "linkedin", "zip_recruiter", "glassdoor", "google", "bayt", "naukri"]
        # for site in sites:
        site_jobs = scrape_jobs(
            # site_name=[site],
            site_name=sites,
            search_term=search_term,
            location=location,
            results_wanted=results_wanted,
            posted_within_days=10,
            proxies=proxies  # Pass the proxy to scrape_jobs
        )
        jobs = site_jobs
        
        return jobs
    except Exception as e:
        return {'status' : 'error', 'message' : str(e)}

# get_jobs('Software Developer','India Chennai',10,"54.248.238.110:80")

# FastAPI endpoint to search jobs
@app.get("/search_jobs/")
async def search_jobs(
    search_term: str = Query(..., description="Job role to search for"),
    location: str = Query(..., description="Location to search jobs in"),
    results_wanted: int = Query(10, le=50, description="Number of results to fetch"),
):
    try:
        # Select a random working proxy
        proxy = random.choice(working_proxies)  # Assuming working_proxies is populated
        print(f"Using proxy: {proxy}")
        
        # Get the jobs using the selected proxy
        jobs = get_jobs(search_term, location, results_wanted, proxy)
        print('jobs ',jobs)
        if isinstance(jobs, dict) and 'status' in jobs and jobs['status'] == 'error':
            return jobs
        df = jobs
        #  # Convert DataFrame and handle non-JSON compliant values
        # print(jobs)
        # # Flatten nested list if it's 3D
        # if isinstance(jobs, list) and len(jobs) == 1 and isinstance(jobs[0], list):
        #     jobs = jobs[0]
        # df = pd.DataFrame(jobs)
        print('ddf',df)
        df = df.replace([np.inf, -np.inf], np.nan)  # Replace infinity with NaN
        df = df.fillna(0)  # Replace NaN with 0 or another appropriate value
        df = df.reset_index(drop=True)
        
        # Return the filtered results as a list of dictionaries
        return df[['id', 'date_posted', 'title', 'company', 'location', 'job_url', 'min_amount', 'max_amount']].to_dict(orient='records')
    except Exception as e:
        return {'status' : 'error',"message": str(e)}

# Function to update proxies and find working ones
working_proxies = []

def update_proxies():
    try:
        proxies = scrape_proxies()
        working_proxies.clear()
        for proxy in proxies:
            if validate_proxy(proxy):
                working_proxies.append(proxy)
    except Exception as e:
        print(f"Error updating proxies: {e}")

# Run the proxy update when FastAPI app starts
# @app.on_event("startup")
# async def on_startup():
#     update_proxies()

# Optional: Retry logic if a proxy fails
def get_jobs_with_retry(search_term: str, location: str, results_wanted: int, max_retries: int = 3):
    jobs = []
    retries = 0
    
    while retries < max_retries:
        proxy = random.choice(working_proxies)  # Choose a proxy
        try:
            jobs = get_jobs(search_term, location, results_wanted, proxy)
            break  # Exit loop if successful
        except Exception as e:
            retries += 1
            print(f"Retrying with a different proxy (Attempt {retries}/{max_retries})")
    
    return jobs


def check_current_ip(proxy=None):
    test_url = "http://httpbin.org/ip"
    accept_language = "en-US,en;q=0.9"
    referer = "https://www.google.com/"
    if proxy:
        proxies = {
            "http": f"http://{proxy}",
            "https": f"http://{proxy}",
        }
        response = requests.get(test_url, proxies=proxies, timeout=5)
        print(response.text)
    else:
        response = requests.get(test_url, timeout=5)
        print(response.text)
    
    return response.json()

# check_current_ip("18.236.175.208:10001")

