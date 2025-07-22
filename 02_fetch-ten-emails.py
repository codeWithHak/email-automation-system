# -------- IMPORTS --------
import os

# Gmail API + Auth libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build



# -------- GMAIL API CONFIG --------
# We only need read access to Gmail
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# -------- STORE SEEN MESSAGE IDS IN MEMORY --------
# We'll use a set to track already seen message IDs (temporary only while script runs)
seen_message_ids = set()



# -------- AUTHENTICATION FUNCTION --------
def authenticate_gmail():
    """
    Authenticates the user with Gmail using OAuth2. Uses token.json to avoid logging in every time.
    """
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return creds

# -------- FETCH AND PRINT NEW EMAILS --------
def check_new_emails(service):
    """
    Fetches recent Gmail messages and prints details of new ones (ignores already seen).
    """
    try:
        results = service.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=10
        ).execute()

        messages = results.get("messages", [])

        for msg in messages:
            msg_id = msg["id"]

            # Skip already seen messages
            if msg_id in seen_message_ids:
                continue

            # Mark message as seen
            seen_message_ids.add(msg_id)

            # Get full message info
            msg_data = service.users().messages().get(userId="me", id=msg_id).execute()
            headers = msg_data["payload"]["headers"]

            sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            snippet = msg_data.get("snippet", "")
    
            # Print to terminal
            print("New Email Arrived!")
            print("From   :", sender)
            print("Subject:", subject)
            print("Preview:", snippet)

            print("-" * 50)

    except Exception as e:
        print("Error while fetching email:", str(e))

# -------- MAIN FUNCTION --------
def main():
    """
    Authenticates Gmail and starts the cron job to check for new emails every minute.
    """
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)
    check_new_emails(service)
    print("Gmail watcher started. Checking every 1 minute...")

# -------- RUN SCRIPT --------
if __name__ == "__main__":
    main()
