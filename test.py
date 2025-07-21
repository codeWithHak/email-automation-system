# to refresh access token if expired
from google.auth.transport.requests import Request

# to load, read, use, and manage Oauth 2.0 tokens
from google.oauth2.credentials import Credentials

# handle complete OAuth flow, opens modal, get access token from google cloud server
from google_auth_oauthlib.flow import InstalledAppFlow

# lets you create a service and use any google api you want (in this case gmail api)
from googleapiclient.discovery import build

