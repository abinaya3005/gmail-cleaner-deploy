import os
import pickle
from flask import Flask, redirect, request, render_template, flash, url_for, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default_secret")

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# ---------------- Gmail API Authentication ----------------
def get_gmail_service():
    creds = None

    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
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
                access_type="offline",
                include_granted_scopes="true"
            )
            session["state"] = state
            return redirect(authorization_url)

    service = build("gmail", "v1", credentials=creds)
    return service

# ---------------- Routes ----------------
@app.route("/")
def index():
    authorized = os.path.exists("token.pickle")
    return render_template("index.html", authorized=authorized)

@app.route("/authorize")
def authorize():
    response = get_gmail_service()
    if isinstance(response, type(redirect("/"))):
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
    elif category == "read":
        query = "is:read"
    elif category == "custom":
        custom_input = request.form.get("custom_email")
        if custom_input:
            if "from:" not in custom_input:
                query = f"from:{custom_input}"
            else:
                query = custom_input
        else:
            flash("❌ Please enter a valid email or query!", "error")
            return redirect(url_for("index"))

    if not query:
        flash("❌ Please select a category or enter a valid query!", "error")
        return redirect(url_for("index"))

    try:
        service = get_gmail_service()
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])

        if not messages:
            flash("ℹ️ No emails found to delete.", "info")
            return redirect(url_for("index"))

        count = 0
        for msg in messages:
            service.users().messages().delete(userId="me", id=msg["id"]).execute()
            count += 1

        flash(f"✅ Deleted {count} emails for query: {query}", "success")
    except HttpError as error:
        flash(f"❌ Error: {error}", "error")

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    if os.path.exists("token.pickle"):
        os.remove("token.pickle")
    flash("🔒 Logged out successfully!", "info")
    return redirect(url_for("index"))

# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
