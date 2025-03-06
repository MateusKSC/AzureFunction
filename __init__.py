import logging
import hmac
import hashlib
import requests
import os
import json

import azure.functions as func

GITHUB_SECRET = os.environ.get('GITHUB_SECRET')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
REPO_OWNER = "MateusKSC"  # Replace
REPO_NAME = "WIP-Capacitacao-Web-APIs-ASP.NET"  # Replace

def verify_signature(data, signature):
    secret = GITHUB_SECRET.encode('utf-8')
    mac = hmac.new(secret, msg=data, digestmod=hashlib.sha256)
    return hmac.compare_digest(f'sha256={mac.hexdigest()}', signature)

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    signature = req.headers.get('X-Hub-Signature-256')
    data = req.get_body()

    if not verify_signature(data, signature):
        return func.HttpResponse("Invalid signature", status_code=401)

    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON", status_code=400)

    if payload['action'] == 'moved':
        column_name = payload['project_card']['column']['name']
        issue_url = payload['project_card']['content_url']
        issue_number = issue_url.split('/')[-1]
        project_number = payload['project_card']['project_url'].split('/')[-1]

        if column_name == 'Review':
            trigger_github_actions(issue_number, project_number)

    return func.HttpResponse("OK", status_code=200)

def trigger_github_actions(issue_number, project_number):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/dispatches"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {
        "event_type": "project_item_moved",
        "client_payload": {
            "column_name": "Review",
            "issue_number": issue_number,
            "repository_name": REPO_NAME,
            "project_number": project_number
        }
    }
    response = requests.post(url, headers=headers, json=data)
    logging.info(f"GitHub API response: {response.status_code}, {response.text}")