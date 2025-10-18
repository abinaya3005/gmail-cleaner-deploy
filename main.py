import os
import pickle
from flask import Flask, redirect, request, render_template, flash, url_for, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

# ---------------- Flask Setup ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "myflasksecretkey123")

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# ---------------- OAuth Flow ----------------
def create_oauth_flow():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "project_id": os.environ.get("GOOGLE_PROJECT_ID", "gmail-cleaner-public"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                "redirect_uris": [os.environ["GOOGLE_REDIRECT_URI"]],
            }
        },
        SCOPES,
    )
    flow.redirect_uri = os.environ["GOOGLE_REDIRECT_URI"]
    return flow

# ---------------- Gmail API Service ----------------
def build_gmail_service():
    """Return Gmail API service. Raise exception if token missing."""
    creds = None
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            raise Exception("No valid credentials. Please authorize Gmail first.")
    service = build("gmail", "v1", credentials=creds)
    return service

# ---------------- Routes ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/authorize")
def authorize():
    """Redirect user to Google OAuth if not authorized"""
    if os.path.exists("token.pickle"):
        flash("✅ Already connected to Gmail!", "success")
        return redirect(url_for("index"))

    flow = create_oauth_flow()
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true"
    )
    session["state"] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    flow = create_oauth_flow()
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    with open("token.pickle", "wb") as token:
        pickle.dump(creds, token)

    flash("✅ Gmail connected successfully!", "success")
    return redirect(url_for("index"))

@app.route("/delete", methods=["POST"])
def delete_emails():
    category = request.form.get("category")
    query = ""

    if category == "flipkart":
        query = "from:flipkart"
    elif category == "amazon":
        query = "from:amazon"
    elif category == "gpay":
        query = "from:gpay"
    elif category == "unread":
        query = "is:unread"
    elif category == "custom":
        query = request.form.get("custom_email")

    if not query:
        flash("❌ Please enter a valid option!", "error")
        return redirect(url_for("index"))

    try:
        service = build_gmail_service()
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])

        count = 0
        for msg in messages:
            service.users().messages().delete(userId="me", id=msg["id"]).execute()
            count += 1

        flash(f"✅ Deleted {count} emails for query: {query}", "success")
    except HttpError as error:
        flash(f"❌ Error: {error}", "error")
    except Exception as e:
        flash(f"❌ {e}", "error")

    return redirect(url_for("index"))

# ---------------- Run App ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
