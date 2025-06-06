import os
import asyncio
import streamlit as st
from dotenv import load_dotenv
from agents import Agent, Runner, AsyncOpenAI, OpenAIChatCompletionsModel, RunConfig, function_tool
import google.generativeai as genai

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText
from googleapiclient.discovery import build
import pickle
import base64
from email import message_from_bytes
from email.policy import default
from googleapiclient.errors import HttpError

import uuid


import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


from google_auth_oauthlib.flow import InstalledAppFlow

load_dotenv()

gemini_api_key = os.getenv("GEMINI_API_KEY")

if not gemini_api_key:
    st.error("GEMINI_API_KEY not found")
    st.stop()

genai.configure(api_key=gemini_api_key)

client = AsyncOpenAI(
    api_key=gemini_api_key,
    base_url="https://generativelanguage.googleapis.com/v1beta"
)

model = OpenAIChatCompletionsModel(
    model="gemini-2.0-flash",
    openai_client=client
)

config = RunConfig(
    model=model,
    model_provider=client,
    tracing_disabled=True
)

agent = Agent(
    name="EmailAgent",
    instructions="You are an email assistant. Help with emails.",
    model=model
)

runner = Runner()

st.title("Email Agent")




SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send"
]


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def authenticate_user():
    if "creds" in st.session_state:
        return st.session_state["creds"]

    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
    creds = flow.run_local_server(port=0)

    st.session_state["creds"] = creds
    return creds

@function_tool
def get_emails():
    creds = authenticate_user()
    try:
        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId="me", maxResults=5).execute()
        messages = results.get("messages", [])

        email_data = []
        for msg in messages:
            try:
                full_msg = service.users().messages().get(
                    userId="me", 
                    id=msg["id"], 
                    format="raw"
                ).execute()
                
                # Safely extract headers
                headers = full_msg.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
                snippet = full_msg.get("snippet", "")
                
                # Decode and parse the raw email with error handling
                raw_data = full_msg.get("raw", "")
                if not raw_data:
                    raise ValueError("No raw data in message")
                
                # Proper base64url decoding
                msg_bytes = base64.urlsafe_b64decode(raw_data.encode('ASCII'))
                
                # Parse the email message
                email_msg = message_from_bytes(msg_bytes, policy=default)
                
                # Get the complete email content
                full_content = email_msg.as_string()
                
                email_data.append({
                    "from": sender,
                    "subject": subject,
                    "snippet": snippet,
                    "full_message": full_content
                })
                
            except Exception as e:
                print(f"Error processing message {msg.get('id')}: {str(e)}")
                continue
                
        return email_data

    except HttpError as error:
        st.error(f"⚠️ Google API error: {error}")
        return []


# st.title("📥 Gmail Inbox Reader")







#summarize

@function_tool
def email_summarizer(message: str)-> str:
     """
    Summarizes the main idea of a given email message.
    Parameters:
        message (str): The full text of the email (can include subject, sender, and body).
    Returns:
        str: A concise summary that captures the key points of the email.
    """
     pass








if st.button("Login to get acces of your email "):
    with st.spinner("logging"):
        emails = get_emails()
        st.success("Login sucessfully!🔥")

        for email in emails:
            st.markdown(f"### {email['subject']}")
            st.write(f"**From:** {email['from']}")
            st.write(f"**Snippet:** {email['snippet']}")
            st.markdown("---")

inbox_agent = Agent(
    name = "get user's email inbox",
    instructions = """
You are an inbox assistant. Your role is to fetch the latest emails from the user's Gmail inbox.
- Use the `get_emails` tool to securely access the user's inbox.
- Only use the tool when explicitly asked to view, read, or check the inbox.
- Do not attempt to summarize or respond to emails yourself—only return the list of emails.
- Each email will include the sender, subject, short snippet, and full message content.
- Return the emails in a clean and readable format suitable for display.
""",
    model = model,
    tools= [get_emails]


)







# if st.button("Summarize all the emails"):
#     with st.spinner("summarizing"):
#         st.success("congo")





























