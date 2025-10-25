import os
import json
from flask import Flask, redirect, request, render_template, flash, url_for, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

# ---------------- Flask Setup ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default_secret")

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# ---------------- Gmail Service ----------------
def get_gmail_service():
    creds = None

    # Load creds from session if available
    if "credentials" in session:
        creds_data = json.loads(session["credentials"])
        creds = Credentials.from_authorized_user_info(creds_data, SCOPES)

    # If no valid creds, start OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            session["credentials"] = creds.to_json()
        else:
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": os.environ["GOOGLE_CLIENT_ID"],
                        "project_id": os.environ.get("GOOGLE_PROJECT_ID", "gmail-cleaner"),
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
            authorization_url, state = flow.authorization_url(
                access_type="offline", include_granted_scopes="true"
            )
            session["state"] = state
            return redirect(authorization_url)

    service = build("gmail", "v1", credentials=creds)
    return service

# ---------------- Routes ----------------

@app.route("/")
def index():
    authorized = "credentials" in session
    return render_template("index.html", authorized=authorized)

@app.route("/authorize")
def authorize():
    response = get_gmail_service()
    # If get_gmail_service() returned a redirect, return it
    from werkzeug.wrappers import Response
    if isinstance(response, Response):
        return response
    flash("✅ Gmail already connected!", "success")
    return redirect(url_for("index"))

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "project_id": os.environ.get("GOOGLE_PROJECT_ID", "gmail-cleaner"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                "redirect_uris": [os.environ["GOOGLE_REDIRECT_URI"]],
            }
        },
        SCOPES,
        state=state,
    )
    flow.redirect_uri = os.environ["GOOGLE_REDIRECT_URI"]

    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    # Save credentials in session
    session["credentials"] = creds.to_json()

    flash("✅ Gmail connected successfully!", "success")
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    flash("🔒 Disconnected from Gmail.", "info")
    return redirect(url_for("index"))

@app.route("/delete", methods=["POST"])
def delete_emails():
    if "credentials" not in session:
        flash("❌ Please connect Gmail first!", "error")
        return redirect(url_for("index"))

    creds_data = json.loads(session["credentials"])
    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
    service = build("gmail", "v1", credentials=creds)

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
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])
        count = 0

        for msg in messages:
            service.users().messages().delete(userId="me", id=msg["id"]).execute()
            count += 1

        flash(f"✅ Deleted {count} emails for query: {query}", "success")
    except HttpError as error:
        flash(f"❌ Error: {error}", "error")

    return redirect(url_for("index"))

# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
