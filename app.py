from flask import Flask, request, render_template, jsonify, session, redirect, url_for
import pandas as pd
import io
import os
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import mimetypes
import logging
import re
import json
from werkzeug.wrappers import Response as WerkzeugResponse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
limiter = Limiter(app, key_func=get_remote_address)
MAX_RECIPIENTS = 500

logging.basicConfig(level=logging.INFO)

SCOPES = ['https://www.googleapis.com/auth/gmail.send','https://www.googleapis.com/auth/userinfo.email',"https://www.googleapis.com/auth/gmail.readonly",'openid', 'profile']
CREDENTIALS_PATH = 'credentials.json'
CLIENT_CONFIG = None

google_creds_json = os.environ.get('GOOGLE_CREDENTIALS_JSON')
if google_creds_json:
    try:
        CLIENT_CONFIG = json.loads(google_creds_json)
        app.logger.info("Successfully loaded Google credentials from environment variable.")
    except json.JSONDecodeError as e:
        app.logger.error(f"Failed to parse GOOGLE_CREDENTIALS_JSON: {e}. Falling back to file if available.")
    except Exception as e:
        app.logger.error(f"An unexpected error occurred loading credentials from environment: {e}")
elif os.path.exists(CREDENTIALS_PATH):
    app.logger.info(f"Using credentials file found at {CREDENTIALS_PATH}.")
else:
    app.logger.warning("Google credentials not found in environment variable GOOGLE_CREDENTIALS_JSON or as credentials.json file.")

def get_google_flow():
    if CLIENT_CONFIG:
        flow = Flow.from_client_config(
            CLIENT_CONFIG,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
    elif os.path.exists(CREDENTIALS_PATH):
        flow = InstalledAppFlow.from_client_secrets_file(
            CREDENTIALS_PATH,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
    else:
        return None
    return flow

def get_credentials(require_redirect=False):
    creds_json = session.get('credentials')
    creds = None
    if creds_json:
        try:
            creds_info = json.loads(creds_json)
            creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
        except Exception as e:
            app.logger.error(f"Error loading credentials from session: {e}. Clearing invalid session credentials.")
            session.pop('credentials', None)
            creds = None
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                session['credentials'] = creds.to_json()
                app.logger.info("Token refreshed successfully and saved to session.")
                return creds 
            except Exception as e:
                app.logger.error(f"Error refreshing token: {e}. Token might be revoked or invalid.")
                session.pop('credentials', None) 
                creds = None 
        if not creds:
            if require_redirect:
                flow = get_google_flow()
                if not flow:
                    app.logger.error("Cannot initiate OAuth flow: Google client configuration not found.")
                    return None 
                authorization_url, state = flow.authorization_url(
                    access_type='offline',
                    prompt='consent',
                    include_granted_scopes='true'
                )
                session['oauth_state'] = state
                app.logger.info(f"Redirecting user to Google for authorization. State: {state}")
                return redirect(authorization_url)
            else:
                 app.logger.info("Credentials not found or invalid, and redirect not required by caller.")
                 return None 
    return creds

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('oauth_state')
    if not state or state != request.args.get('state'):
        app.logger.error("OAuth callback state mismatch.")
        return jsonify({"success": False, "error": "Invalid state parameter."}), 400
    session.pop('oauth_state', None)
    flow = get_google_flow()
    if not flow:
       app.logger.error("OAuth callback cannot proceed: Google client configuration not found.")
       return jsonify({"success": False, "error": "Server configuration error."}), 500
    try:
        authorization_response = request.url
        if 'http://' in authorization_response and not app.debug:
             authorization_response = authorization_response.replace('http://', 'https://', 1)
             app.logger.warning("Replaced http with https in authorization response URL for production.")
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        session['credentials'] = credentials.to_json()
        app.logger.info("OAuth flow completed successfully. Credentials stored in session.")
        try:
            service = build('oauth2', 'v2', credentials=credentials)
            user_info = service.userinfo().get().execute()
            session['user_email'] = user_info.get('email')
            app.logger.info(f"User authenticated: {session.get('user_email')}")
        except Exception as e:
             app.logger.error(f"Failed to fetch user info after OAuth: {e}")
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Error during OAuth token fetch: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": f"Failed to fetch OAuth token: {str(e)}"}), 400

def create_message(sender, to, subject, body_html, attachments=None):
    message = MIMEMultipart('related')
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    msg_alternative = MIMEMultipart('alternative')
    message.attach(msg_alternative)
    msg_alternative.attach(MIMEText(body_html, 'html'))
    if attachments:
        for file_storage in attachments:
            if file_storage and file_storage.filename:
                content_type, encoding = mimetypes.guess_type(file_storage.filename)
                if content_type is None or encoding is not None:
                    content_type = 'application/octet-stream'
                main_type, sub_type = content_type.split('/', 1)
                try:
                    part = MIMEBase(main_type, sub_type)
                    file_content = file_storage.read()
                    part.set_payload(file_content)
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', 'attachment', filename=file_storage.filename)
                    message.attach(part)
                    file_storage.seek(0)
                except Exception as e:
                    app.logger.warning(f"Could not attach file {file_storage.filename}: {e}")
            else:
                 app.logger.warning("Skipping an invalid attachment object.")
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_gmail_message(service, user_id, message):
    try:
        sent_message = service.users().messages().send(userId=user_id, body=message).execute()
        app.logger.info(f"Message Id: {sent_message['id']} sent.")
        return sent_message
    except HttpError as error:
        app.logger.error(f'An error occurred sending email: {error}')
        raise error 
    except Exception as e:
        app.logger.error(f'An unexpected error occurred sending email: {e}')
        raise e

def is_valid_email(email):
    if not email or '@' not in email:
        return False
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(pattern, email) is not None

@app.route('/', methods=['GET'])
def index():
    creds_or_redirect = get_credentials(require_redirect=True)
    if isinstance(creds_or_redirect, WerkzeugResponse):
        return creds_or_redirect
    if creds_or_redirect is None and not (CLIENT_CONFIG or os.path.exists(CREDENTIALS_PATH)):
         app.logger.error("Cannot render index: Google client configuration not found.")
         return "Server configuration error: Google API credentials are not set up correctly. Please contact the administrator.", 500
    if creds_or_redirect is None:
        app.logger.warning("Index route called without credentials, redirect should have happened. Check OAuth flow.")
        return "Authentication error. Please try reloading.", 500
    user_email = session.get('user_email', 'Unknown User')
    return render_template('index.html', user_email=user_email)

@app.route('/send-emails', methods=['POST'])
@limiter.limit("5 per minute")
def send_emails():
    creds = get_credentials(require_redirect=False)
    if not creds:
        app.logger.error("Authentication failed in /send-emails endpoint (credentials missing or expired).")
        return jsonify({"success": False, "error": "Authentication required or expired. Please reload the page to sign in again.", "statusCode": 401}), 401
    try:
        service = build('gmail', 'v1', credentials=creds)
        sender_email = session.get('user_email')
        if not sender_email:
            try:
                profile = service.users().getProfile(userId='me').execute()
                sender_email = profile['emailAddress']
                session['user_email'] = sender_email
                app.logger.info(f"Re-fetched sender email: {sender_email}")
            except HttpError as profile_err:
                 app.logger.error(f"Failed to get Gmail profile even with credentials: {profile_err}")
                 if profile_err.resp.status in [401, 403]:
                     session.pop('credentials', None)
                     session.pop('user_email', None)
                     return jsonify({"success": False, "error": f"Gmail authentication error ({profile_err.resp.status}). Your session may have expired. Please reload the page.", "statusCode": 401}), 401
                 return jsonify({"success": False, "error": f"Failed to verify sender identity: {profile_err}", "statusCode": 500}), 500
            except Exception as profile_e:
                 app.logger.error(f"Unexpected error fetching profile: {profile_e}")
                 return jsonify({"success": False, "error": f"Unexpected error verifying sender: {profile_e}", "statusCode": 500}), 500
        app.logger.info(f"Authenticated as {sender_email} for sending.")
    except HttpError as e:
         app.logger.error(f"Failed to build Gmail service or get profile: {e}")
         if e.resp.status == 401 or e.resp.status == 403:
             session.pop('credentials', None)
             session.pop('user_email', None)
             return jsonify({"success": False, "error": f"Gmail authentication error ({e.resp.status}). Please reload the page and re-authenticate.", "statusCode": 401}), 401
         return jsonify({"success": False, "error": f"Failed to connect to Gmail service: {e}", "statusCode": 500}), 500
    except Exception as e:
         app.logger.error(f"Unexpected error building Gmail service: {e}")
         return jsonify({"success": False, "error": f"Unexpected error connecting to Gmail: {e}", "statusCode": 500}), 500
    mode = request.form.get('mode', 'csv')
    subject_template = request.form.get('subject_template', '')
    body_template = request.form.get('body_template', '')
    attachments = request.files.getlist('attachments')
    results = []
    total_recipients = 0
    if not subject_template or not body_template:
         return jsonify({"success": False, "error": "Subject and Body templates are required."}), 400
    try:
        if mode == 'csv':
            recipient_template = request.form.get('recipient_template')
            csv_file = request.files.get('csv_file')
            if not csv_file:
                return jsonify({"success": False, "error": "CSV file is required for CSV mode."}), 400
            if not recipient_template:
                return jsonify({"success": False, "error": "Recipient template is required for CSV mode."}), 400
            try:
                csv_content = csv_file.read().decode('utf-8-sig')
                df = pd.read_csv(io.StringIO(csv_content), dtype=str)
                df = df.fillna('')
                df.columns = [col.strip() for col in df.columns]
                csv_headers = df.columns.tolist()
            except Exception as e:
                 app.logger.error(f"Error processing CSV file: {e}")
                 return jsonify({"success": False, "error": f"Error reading or parsing CSV file: {e}. Ensure it's a valid UTF-8 encoded CSV with headers."}), 400
            if df.empty:
                 return jsonify({"success": False, "error": "CSV file is empty or contains only headers."}), 400
            if len(df) > MAX_RECIPIENTS:
                 return jsonify({"success": False, "error": f"Too many recipients in CSV. Maximum allowed is {MAX_RECIPIENTS}."}), 400
            total_recipients = len(df)
            app.logger.info(f"Starting CSV email sending process for {total_recipients} rows.")
            for index, row in df.iterrows():
                row_num = index + 1
                recipient_email = recipient_template
                subject = subject_template
                body = body_template
                placeholders_found = set(re.findall(r'\{(.+?)\}', recipient_template + subject_template + body_template))
                missing_placeholders = [ph for ph in placeholders_found if ph not in csv_headers]
                if missing_placeholders:
                    reason = f"Unresolved placeholders: {', '.join(missing_placeholders)}. Check spelling/case against CSV headers."
                    results.append({"row": row_num, "status": "skipped", "reason": reason , "recipient": f"Row {row_num} data"})
                    app.logger.warning(f"Skipping row {row_num}: {reason}")
                    continue
                try:
                    for col in csv_headers:
                        placeholder = f'{{{col}}}'
                        value = str(row[col]) if pd.notna(row[col]) else ''
                        recipient_email = recipient_email.replace(placeholder, value)
                        subject = subject.replace(placeholder, value)
                        body = body.replace(placeholder, value)
                    recipient_email = recipient_email.strip()
                    if not is_valid_email(recipient_email):
                        results.append({"row": row_num, "status": "skipped", "reason": "Invalid recipient email format", "recipient": recipient_email or f"Row {row_num} processing"})
                        app.logger.warning(f"Skipping row {row_num}: Invalid recipient email '{recipient_email}' generated from template '{recipient_template}'")
                        continue
                    app.logger.info(f"Attempting to send email to: {recipient_email} (Row {row_num})")
                    email_message = create_message(sender_email, recipient_email, subject, body, attachments)
                    send_gmail_message(service, 'me', email_message)
                    results.append({"row": row_num, "status": "sent", "recipient": recipient_email})
                except HttpError as http_err:
                    error_details = str(http_err)
                    reason = f"Gmail API Error: {error_details}"
                    results.append({"row": row_num, "status": "failed", "reason": reason, "recipient": recipient_email or f"Row {row_num} processing"})
                    app.logger.error(f"Failed sending for row {row_num} (recipient: {recipient_email}): {reason}")
                    if http_err.resp.status in [401, 403]:
                         session.pop('credentials', None)
                         session.pop('user_email', None)
                         app.logger.error("Critical auth error during send loop. Aborting.")
                         results.append({"row": "N/A", "status": "aborted", "reason": "Authentication failed mid-process. Reload page.", "recipient": "Process Halted"})
                         break
                except Exception as e:
                    error_details = str(e)
                    reason = f"Unexpected Error: {error_details}"
                    results.append({"row": row_num, "status": "failed", "reason": reason, "recipient": recipient_email or f"Row {row_num} processing"})
                    app.logger.error(f"Unexpected error sending for row {row_num} (recipient: {recipient_email}): {reason}")
                    import traceback
                    traceback.print_exc()
        elif mode == 'manual':
            manual_recipients_raw = request.form.get('manual_recipients', '')
            manual_recipients = [email.strip() for email in re.split(r'[,\s\n]+', manual_recipients_raw) if email.strip()]
            if not manual_recipients:
                 return jsonify({"success": False, "error": "No valid recipient emails provided in Manual mode."}), 400
            if len(manual_recipients) > MAX_RECIPIENTS:
                 return jsonify({"success": False, "error": f"Too many recipients provided. Maximum allowed is {MAX_RECIPIENTS}."}), 400
            total_recipients = len(manual_recipients)
            app.logger.info(f"Starting Manual email sending process for {total_recipients} recipients.")
            for index, recipient_email in enumerate(manual_recipients):
                 recipient_num = index + 1
                 if not is_valid_email(recipient_email):
                     results.append({"row": recipient_num, "status": "skipped", "reason": "Invalid email format", "recipient": recipient_email})
                     app.logger.warning(f"Skipping manual recipient #{recipient_num}: Invalid email format '{recipient_email}'")
                     continue
                 try:
                     subject = subject_template
                     body = body_template
                     placeholders = re.findall(r'\{.*?\}', subject + body)
                     if placeholders:
                        app.logger.warning(f"Placeholders found in template for manual recipient {recipient_email}. They will be sent literally as placeholders are not replaced in manual mode.")
                     app.logger.info(f"Attempting to send manual email to: {recipient_email} (#{recipient_num})")
                     email_message = create_message(sender_email, recipient_email, subject, body, attachments)
                     send_gmail_message(service, 'me', email_message)
                     results.append({"row": recipient_num, "status": "sent", "recipient": recipient_email})
                 except HttpError as http_err:
                    error_details = str(http_err)
                    reason = f"Gmail API Error: {error_details}"
                    results.append({"row": recipient_num, "status": "failed", "reason": reason, "recipient": recipient_email})
                    app.logger.error(f"Failed sending to manual recipient {recipient_email} (#{recipient_num}): {reason}")
                    if http_err.resp.status in [401, 403]:
                         session.pop('credentials', None)
                         session.pop('user_email', None)
                         app.logger.error("Critical auth error during send loop. Aborting.")
                         results.append({"row": "N/A", "status": "aborted", "reason": "Authentication failed mid-process. Reload page.", "recipient": "Process Halted"})
                         break
                 except Exception as e:
                    error_details = str(e)
                    reason = f"Unexpected Error: {error_details}"
                    results.append({"row": recipient_num, "status": "failed", "reason": reason, "recipient": recipient_email})
                    app.logger.error(f"Unexpected error sending to manual recipient {recipient_email} (#{recipient_num}): {reason}")
                    import traceback
                    traceback.print_exc()
        else:
             return jsonify({"success": False, "error": "Invalid mode specified."}), 400
        success_count = sum(1 for r in results if r['status'] == 'sent')
        skipped_count = sum(1 for r in results if r['status'] == 'skipped')
        failed_count = sum(1 for r in results if r['status'] == 'failed')
        aborted_count = sum(1 for r in results if r['status'] == 'aborted')
        summary_message = f"Process completed ({mode} mode). Target(s): {total_recipients}. Sent: {success_count}, Skipped: {skipped_count}, Failed: {failed_count}."
        if aborted_count > 0:
             summary_message += f" Aborted: {aborted_count} due to critical error (likely auth)."
        app.logger.info(summary_message)
        return jsonify({"success": True, "message": summary_message, "results": results})
    except pd.errors.EmptyDataError:
        app.logger.error("Attempted to process an empty or invalid CSV file.")
        return jsonify({"success": False, "error": "CSV file is empty or invalid."}), 400
    except Exception as e:
        app.logger.error(f"A critical error occurred in /send-emails: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": f"An unexpected server error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    if not (CLIENT_CONFIG or os.path.exists(CREDENTIALS_PATH)):
         print("ERROR: Google API credentials are not configured.")
         print("Set the GOOGLE_CREDENTIALS_JSON environment variable or place credentials.json in the root directory.")
    app.run(debug=True, port=5000)