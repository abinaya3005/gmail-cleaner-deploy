import os
import pickle
from flask import Flask, redirect, request, render_template, session, url_for, flash
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default_secret")

# Gmail API Scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# OAuth setup
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # for local testing


@app.route("/")
def index():
    if "credentials" in session:
        return render_template("index.html", connected=True)
    return render_template("index.html", connected=False)


@app.route("/authorize")
def authorize():
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")

    if not client_id or not client_secret:
        return "Missing Google OAuth credentials in environment variables.", 500

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uris": [url_for("oauth2callback", _external=True)],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
    )

    flow.redirect_uri = url_for("oauth2callback", _external=True)
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    session["state"] = state
    return redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")

    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uris": [url_for("oauth2callback", _external=True)],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        state=state,
    )

    flow.redirect_uri = url_for("oauth2callback", _external=True)
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    creds = flow.credentials

    # Save only safe parts in session
    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
    }

    flash("✅ Connected to Gmail!", "success")
    return redirect(url_for("index"))


@app.route("/delete", methods=["POST"])
def delete_emails():
    creds_data = session.get("credentials")
    if not creds_data:
        flash("Please connect Gmail first.", "error")
        return redirect(url_for("index"))

    # ✅ FIX: Safely rebuild credentials
    if not creds_data or "token" not in creds_data:
        flash("Session expired or invalid credentials. Please reconnect Gmail.", "error")
        return redirect(url_for("index"))

    creds = Credentials(
        token=creds_data.get("token"),
        refresh_token=creds_data.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        scopes=SCOPES,
    )

    try:
        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId="me", q="is:read").execute()
        messages = results.get("messages", [])

        if not messages:
            flash("No read emails found to delete.", "info")
            return redirect(url_for("index"))

        for msg in messages:
            service.users().messages().trash(userId="me", id=msg["id"]).execute()

        flash(f"✅ {len(messages)} read emails moved to trash!", "success")

    except HttpError as error:
        flash(f"An error occurred: {error}", "error")

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("credentials", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
