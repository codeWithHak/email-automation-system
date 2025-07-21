# --------- IMPORTS ---------
import sqlite3  # For storing emails locally in a database
import os       # To check if files like 'token.json' exist

# Gmail API and authentication libraries from Google
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --------- DATABASE SETUP ---------
# Connect to (or create) a SQLite database file called 'mails.db'
conn = sqlite3.connect("mails.db")
cursor = conn.cursor()

# Create a table to store emails if it doesn't already exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS huzair_mails1 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- auto-incrementing ID for each row
    sender TEXT,                           -- email sender
    subject TEXT,                          -- email subject line
    snippet TEXT                           -- short preview of the email content
)
""")
conn.commit()  # Save table creation to disk

# --------- GMAIL API SETUP ---------
# This defines what permissions your app is requesting
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
# 'readonly' = you can only read emails, not send/delete

# --------- AUTHENTICATION FUNCTION ---------
def authenticate_gmail():
    """
    Handles Google OAuth2 login. Reuses token if it exists, 
    otherwise starts new login flow and saves the token.
    """
    creds = None

    # Check if we've already saved login credentials in token.json
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    # If no valid credentials, start login process
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Refresh expired token
            creds.refresh(Request())
        else:
            # Start a new login session (opens browser for Google login)
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)  # auto-chooses a free port

        # Save the new token for future runs
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return creds  # Return credentials to be used with Gmail API

# --------- EMAIL FETCHER FUNCTION ---------
def fetch_and_save_emails(service):
    """
    Fetches latest emails from Gmail inbox and saves them into SQLite database.
    """
    # Request latest 5 messages from the user's inbox
    results = service.users().messages().list(
        userId="me",           # 'me' = current authenticated user
        labelIds=["INBOX"],    # Only fetch from INBOX
        maxResults=5           # Limit to 5 emails
    ).execute()

    messages = results.get("messages", [])  # Get list of message metadata

    for msg in messages:
        # Get full message data (headers, snippet, etc.)
        msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()

        # Extract headers to get sender and subject
        headers = msg_data["payload"]["headers"]
        sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        snippet = msg_data.get("snippet", "")  # Short preview text from Gmail

        # Save email data into database
        cursor.execute(
            "INSERT INTO huzair_mails1 (sender, subject, snippet) VALUES (?, ?, ?)",
            (sender, subject, snippet)
        )
        conn.commit()  # Save to disk

        # Print to console (for confirmation/debugging)
        print("Saved email:")
        print("From   :", sender)
        print("Subject:", subject)
        print("Preview:", snippet)
        print("-" * 40)

# --------- MAIN FUNCTION ---------
def main():
    """
    Main program entry point. Authenticates user and fetches/saves emails.
    """
    creds = authenticate_gmail()  # Step 1: Login to Gmail
    service = build("gmail", "v1", credentials=creds)  # Step 2: Connect to Gmail API
    fetch_and_save_emails(service)  # Step 3: Get emails and store them

# --------- RUN MAIN ---------
if __name__ == "__main__":
    main()
