# -------- IMPORTS --------
import os
import time
import base64
from rich import print
import sqlite3

# Gmail API + Auth libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Scheduler for running the fetch job on interval
from apscheduler.schedulers.background import BackgroundScheduler




# DATABASE CONFIG

connection = sqlite3.connect("mails.db", check_same_thread=False)

cursor = connection.cursor()

    #         print("New Email Arrived!")
    #         print("From   :", sender)
    #         print("Subject:", subject)
    #         print("Date:", date)
    #         print("Mail:", mail)
    #         print("-" * 50)

create_mail_table_query = "CREATE TABLE IF NOT EXISTS huzair_mails (id TEXT PRIMARY KEY, sender TEXT, subject TEXT, date TEXT, mail TEXT)"

create_attachment_table_query = """

                CREATE TABLE IF NOT EXISTS huzair_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT,
                file_name TEXT,
                file_path TEXT,
                file_type TEXT,
                FOREIGN KEY (email_id) REFERENCES huzair_mails(id) ON DELETE CASCADE
            )
                
                """


cursor.execute(create_mail_table_query)
cursor.execute(create_attachment_table_query)
# -------- GMAIL API CONFIG --------
# We only need read access to Gmail
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# -------- STORE SEEN MESSAGE IDS IN MEMORY --------
# We'll use a set to track already seen message IDs (temporary only while script runs)
seen_message_ids = set()

# this function was just checking parent and returnong None
# def extract_plain_text_body(msg_data):
    # """
    # Extracts and decodes the plain text body of the Gmail message.
    # """
    # try:
    #     parts = msg_data["payload"]["parts"]
    #     for part in parts:
    #         print("MIME TYPE:", part["mimeType"])
    #         if part["mimeType"] == "text/plain":
    #             body_data = part["body"]["data"]
    #             decoded_bytes = base64.urlsafe_b64decode(body_data)
    #             return decoded_bytes.decode("utf-8")
            
    #         elif part["mimeType"] == "text/html":
    #             body_data = part["body"]["data"]
    #             html = base64.urlsafe_b64decode(body_data).decode("utf-8")
    #             return f"[HTML Email Detected]\n{html}"
    # except:
    #     # If 'parts' not available, try root body
    #     try:
    #         body_data = msg_data["payload"]["body"]["data"]
    #         decoded_bytes = base64.urlsafe_b64decode(body_data)
    #         return decoded_bytes.decode("utf-8")
    #     except:
    #         return "[No body found]"

def extract_plain_text_body(msg_data):
    try:
        def find_plain_text(parts):
            for part in parts:
                mime_type = part.get("mimeType", "")
                if mime_type == "text/plain":
                    body_data = part["body"].get("data")
                    if body_data:
                        decoded_bytes = base64.urlsafe_b64decode(body_data)
                        return decoded_bytes.decode("utf-8")
                elif mime_type.startswith("multipart/"):
                    nested = part.get("parts", [])
                    result = find_plain_text(nested)
                    if result:
                        return result
            return None

        payload = msg_data.get("payload", {})
        if payload.get("mimeType", "").startswith("multipart/"):
            return find_plain_text(payload.get("parts", [])) or "[No body found]"
        elif payload.get("mimeType") == "text/plain":
            body_data = payload["body"].get("data")
            if body_data:
                decoded_bytes = base64.urlsafe_b64decode(body_data)
                return decoded_bytes.decode("utf-8")
        return "[No body found]"
    except Exception as e:
        return f"[Error extracting body: {str(e)}]"


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
            maxResults=1
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
       

            # GETTING ATTACHMENTS

            # loop over the paayload of every message and get parts from them then check if parts have filename if yes it's a valid attachment
            for part in msg_data["payload"].get("parts",[]):
           
                if part["filename"]:
                    file_name = part["filename"]
                    file_type = part.get("mimeType", "application/octet-stream")
                    attachment_id = part["body"].get("attachmentId")
            
                    attachment = service.users().messages().attachments().get(userId="me", messageId=msg_id, id=attachment_id).execute()
                    
                    # DECODE THE DATA FROM BASE 64 TO IT'S CORRESPONDING FORMAT
                    file_data = base64.urlsafe_b64decode(attachment["data"])

                    # SET THE FILE PATH FOR CURRENT DIRECTORY
                    file_path = os.path.join("attachments", part["filename"])
                    
                    # WRITING ATTAHCMENTS IN LOCAL FILE
                    with open(file_path, "wb") as f:
                        f.write(file_data)

                    insert_attachment_query = f"INSERT INTO huzair_attachments (email_id, file_name, file_path, file_type) VALUES('{msg_id}', '{file_name}', '{file_path}', '{file_type}')"
                    cursor.execute(insert_attachment_query)

                    print("Attachment Stored In Database")
            headers = msg_data["payload"]["headers"]
            print(headers)
            sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            date = next((h["value"] for h in headers if h["name"] == "Date"), "No Subject")
            mail = extract_plain_text_body(msg_data)


            # Print to terminal
            print("New Email Arrived!")
            print("From   :", sender)
            print("Subject:", subject)
            print("Date:", date)
            print("Mail:", mail)
            print("-" * 50)

            insert_mail_query = f"INSERT OR IGNORE INTO huzair_mails (id,sender,subject,date,mail) VALUES('{msg_id}', '{sender}', '{subject}', '{date}', '{mail}')"
            cursor.execute(insert_mail_query)
            connection.commit()
            
            print("Email Stored In DB")

    except Exception as e:
        print("Error while fetching email:", str(e))

# -------- MAIN FUNCTION --------
def main():
    """
    Authenticates Gmail and starts the cron job to check for new emails every minute.
    """
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    scheduler = BackgroundScheduler()
    scheduler.add_job(lambda: check_new_emails(service), 'interval', minutes=1)
    scheduler.start()

    print("Gmail watcher started. Checking every 1 minute...")

    # Keep the script alive
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print("Stopping Gmail watcher...")
        scheduler.shutdown()

# -------- RUN SCRIPT --------
if __name__ == "__main__":
    main()
