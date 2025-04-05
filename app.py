from flask import Flask, request, render_template, jsonify, session, redirect, url_for, current_app
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
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sys
from oauthlib.oauth2.rfc6749.errors import InsecureTransportError

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH_MB', 20)) * 1024 * 1024
app.config['MAX_TOTAL_ATTACHMENT_SIZE_MB'] = int(os.environ.get('MAX_TOTAL_ATTACHMENT_SIZE_MB', 15))
app.config['MAX_ATTACHMENTS_PER_EMAIL'] = int(os.environ.get('MAX_ATTACHMENTS_PER_EMAIL', 5))
app.config['MAX_CSV_RECIPIENTS'] = int(os.environ.get('MAX_CSV_RECIPIENTS', 1000))
app.config['MAX_MANUAL_RECIPIENTS'] = int(os.environ.get('MAX_MANUAL_RECIPIENTS', 100))
app.config['SEND_EMAIL_RATE_LIMIT'] = os.environ.get('SEND_EMAIL_RATE_LIMIT', "15 per minute")
app.config['GLOBAL_RATE_LIMIT_DAY'] = os.environ.get('GLOBAL_RATE_LIMIT_DAY', "200 per day")
app.config['GLOBAL_RATE_LIMIT_HOUR'] = os.environ.get('GLOBAL_RATE_LIMIT_HOUR', "50 per hour")

logging.basicConfig(level=logging.INFO)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[app.config['GLOBAL_RATE_LIMIT_DAY'], app.config['GLOBAL_RATE_LIMIT_HOUR']],
    storage_uri=os.environ.get('LIMITER_STORAGE_URI', "memory://"),
    strategy="fixed-window"
)

SCOPES = ['https://www.googleapis.com/auth/gmail.send','https://www.googleapis.com/auth/userinfo.email','openid']
CREDENTIALS_PATH = 'credentials.json'
CLIENT_CONFIG = None

google_creds_json = os.environ.get('GOOGLE_CREDENTIALS_JSON')
if google_creds_json:
    try:
        CLIENT_CONFIG = json.loads(google_creds_json)
        app.logger.info("Successfully loaded Google credentials from environment variable.")
    except json.JSONDecodeError as e:
        app.logger.error(f"Failed to parse GOOGLE_CREDENTIALS_JSON: {e}. Falling back to file if available.")
        CLIENT_CONFIG = None
    except Exception as e:
        app.logger.error(f"An unexpected error occurred loading credentials from environment: {e}")
        CLIENT_CONFIG = None

if not CLIENT_CONFIG and os.path.exists(CREDENTIALS_PATH):
    app.logger.info(f"Using credentials file found at {CREDENTIALS_PATH}.")
    try:
        with open(CREDENTIALS_PATH, 'r') as f:
            client_secrets_content = json.load(f)
            if 'web' in client_secrets_content or 'installed' in client_secrets_content:
                CLIENT_CONFIG = client_secrets_content
            else:
                app.logger.error(f"{CREDENTIALS_PATH} does not seem to contain valid client secrets structure.")
    except json.JSONDecodeError as e:
        app.logger.error(f"Failed to parse {CREDENTIALS_PATH}: {e}")
    except Exception as e:
        app.logger.error(f"Error reading {CREDENTIALS_PATH}: {e}")
elif not CLIENT_CONFIG:
    app.logger.warning("Google credentials not found in environment variable GOOGLE_CREDENTIALS_JSON or as credentials.json file.")

def get_google_flow():
    if CLIENT_CONFIG:
        try:
            redirect_uri = url_for('oauth2callback', _external=True)
            is_local_insecure = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT') == '1'

            if is_local_insecure:
                if redirect_uri.startswith('https://'):
                    redirect_uri = redirect_uri.replace('https://', 'http://', 1)
                    app.logger.warning("OAUTHLIB_INSECURE_TRANSPORT=1: Using HTTP redirect_uri for local dev.")
                os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
            else:
                if not redirect_uri.startswith('https://'):
                    app.logger.warning(f"Generated redirect_uri was not HTTPS ({redirect_uri}). Forcing HTTPS. Check ProxyFix/headers.")
                    redirect_uri = redirect_uri.replace('http://', 'https://', 1)
                if 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ:
                     del os.environ['OAUTHLIB_INSECURE_TRANSPORT'] # Remove if it was somehow set

            app.logger.info(f"Final redirect_uri for Google Flow: {redirect_uri}")

            flow = Flow.from_client_config(
                CLIENT_CONFIG,
                scopes=SCOPES,
                redirect_uri=redirect_uri
            )
            return flow
        except Exception as e:
            app.logger.error(f"Error creating Flow from client_config: {e}", exc_info=True)
            return None

    elif os.path.exists(CREDENTIALS_PATH) and not CLIENT_CONFIG:
        try:
            redirect_uri = url_for('oauth2callback', _external=True)
            is_local_insecure = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT') == '1'

            if is_local_insecure:
                 if redirect_uri.startswith('https://'):
                     redirect_uri = redirect_uri.replace('https://', 'http://', 1)
                 os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
            else:
                 if not redirect_uri.startswith('https://'):
                     redirect_uri = redirect_uri.replace('http://', 'https://', 1) # Force https if needed
                 if 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ:
                     del os.environ['OAUTHLIB_INSECURE_TRANSPORT']

            app.logger.warning("Using InstalledAppFlow based on credentials.json. This may not be suitable for production.")
            app.logger.info(f"Final redirect_uri for InstalledAppFlow: {redirect_uri}")
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_PATH,
                scopes=SCOPES,
                redirect_uri=redirect_uri
            )
            return flow
        except Exception as e:
            app.logger.error(f"Error creating Flow from client_secrets_file {CREDENTIALS_PATH}: {e}", exc_info=True)
            return None
    else:
        app.logger.error("Cannot get Google Flow: No valid client configuration loaded.")
        return None

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
                app.logger.info(f"Redirecting user to Google for authorization. State: {state}, URL: {authorization_url}")
                return redirect(authorization_url)
            else:

                app.logger.info("Credentials not found or invalid, and redirect not required by caller.")
                return None
    return creds

@app.route('/privacy', methods=['GET'])
def privacy():
    return render_template('privacy.html')

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('oauth_state')
    app.logger.info(f"OAuth Callback received. Session state: {state}, Request state: {request.args.get('state')}")
    app.logger.info(f"Request URL: {request.url}") # This should now be HTTPS on Render
    app.logger.info(f"Request Args: {request.args}")

    if not state or state != request.args.get('state'):
        app.logger.error("OAuth callback state mismatch.")
        return jsonify({"success": False, "error": "Invalid state parameter."}), 400
    session.pop('oauth_state', None)

    flow = get_google_flow()
    if not flow:
        app.logger.error("OAuth callback cannot proceed: Google client configuration not found.")
        return jsonify({"success": False, "error": "Server configuration error."}), 500

    try:
        # Use the full request URL (which should be HTTPS now thanks to ProxyFix)
        authorization_response = request.url
        app.logger.info(f"Using authorization response URL for fetch_token: {authorization_response}")

        # The check for http:// should ideally not be needed now, but keep as safety
        # Make sure OAUTHLIB_INSECURE_TRANSPORT is NOT 1 in production
        if 'http://' in authorization_response and not app.debug and os.environ.get('OAUTHLIB_INSECURE_TRANSPORT') != '1':
             app.logger.warning("HTTP detected in authorization_response URL on production. Attempting to replace with HTTPS. Check ProxyFix.")
             authorization_response = authorization_response.replace('http://', 'https://', 1)


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


        return redirect(url_for('main_app'))

    # Catch specific OAuth errors
    except InsecureTransportError as e:
         app.logger.error(f"InsecureTransportError during OAuth token fetch: {e}", exc_info=True)
         error_message = "OAuth Error: Insecure transport (HTTP) is not allowed. Ensure app is accessed via HTTPS."
         return redirect(url_for('index', error='transport_error', details=str(e)[:200]))
    except Exception as e:
        app.logger.error(f"Error during OAuth token fetch: {e}", exc_info=True)
        error_message = f"Failed to fetch OAuth token: {str(e)}"

        error_param = "oauth_error"
        if "invalid_grant" in str(e).lower(): # Example of catching specific grant errors
             error_param = "invalid_grant"
             error_message = "OAuth Error: Invalid grant or token expired/revoked. Please sign in again."
        elif "redirect_uri_mismatch" in str(e).lower(): # Catch mismatch explicitly if it happens here
             error_param = "redirect_uri_mismatch"
             error_message = "OAuth Error: Redirect URI mismatch. Please contact support."


        session.pop('credentials', None)
        session.pop('user_email', None)
        return redirect(url_for('index', error=error_param, details=str(e)[:200]))


def create_message(sender, to, subject, body_html, attachments=None):
    message = MIMEMultipart('related')
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject

    msg_alternative = MIMEMultipart('alternative')
    message.attach(msg_alternative)


    msg_alternative.attach(MIMEText(body_html, 'html', _charset='utf-8'))

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
                    part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file_storage.filename))
                    message.attach(part)
                    file_storage.seek(0)
                except Exception as e:
                    app.logger.warning(f"Could not attach file {file_storage.filename}: {e}")
            else:
                 app.logger.warning("Skipping an invalid attachment object (no filename or object).")


    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_gmail_message(service, user_id, message):
    try:
        sent_message = service.users().messages().send(userId=user_id, body=message).execute()
        app.logger.info(f"Message Id: {sent_message['id']} sent.")
        return sent_message
    except HttpError as error:

        app.logger.error(f"An error occurred sending email via Gmail API: {error.resp.status} - {error.content}")
        raise error
    except Exception as e:
        app.logger.error(f"An unexpected error occurred sending email: {e}")
        raise e


def is_valid_email(email):
    if not email or '@' not in email or ' ' in email:
        return False

    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None


@app.errorhandler(413)
def request_entity_too_large(error):
    max_size_mb = current_app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)
    return jsonify({"success": False, "error": f"Request size exceeds the limit ({max_size_mb:.1f} MB). This usually means the total size of uploaded files is too large.", "statusCode": 413}), 413

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(success=False, error=f"Rate limit exceeded: {e.description}. Please try again later.", statusCode=429), 429

@app.route('/', methods=['GET'])
def index():

    error = request.args.get('error')
    details = request.args.get('details')
    return render_template('index.html', error=error, details=details)


@app.route('/app', methods=['GET'])
def main_app():
    creds_or_redirect = get_credentials(require_redirect=True)

    if isinstance(creds_or_redirect, WerkzeugResponse):

        return creds_or_redirect

    if creds_or_redirect is None:


        if not (CLIENT_CONFIG or os.path.exists(CREDENTIALS_PATH)):
            app.logger.error("Cannot render main app: Google client configuration not found.")

            return redirect(url_for('index', error='config_missing'))
        else:

            app.logger.warning("App route reached without valid credentials, despite require_redirect=True. Config exists.")

            return redirect(url_for('index', error='auth_failed'))



    user_email = session.get('user_email', 'Unknown User')
    if user_email == 'Unknown User':

         try:
            service = build('oauth2', 'v2', credentials=creds_or_redirect)
            user_info = service.userinfo().get().execute()
            user_email = user_info.get('email', 'Unknown User')
            session['user_email'] = user_email
            app.logger.info(f"Fetched user email for session: {user_email}")
         except Exception as e:
             app.logger.error(f"Failed to fetch user info for app page display: {e}")


    limits = {
        'MAX_TOTAL_ATTACHMENT_SIZE_MB': app.config['MAX_TOTAL_ATTACHMENT_SIZE_MB'],
        'MAX_ATTACHMENTS_PER_EMAIL': app.config['MAX_ATTACHMENTS_PER_EMAIL'],
        'MAX_MANUAL_RECIPIENTS': app.config['MAX_MANUAL_RECIPIENTS'],
        'MAX_CSV_RECIPIENTS': app.config['MAX_CSV_RECIPIENTS']
    }

    return render_template('app.html', user_email=user_email, limits=limits)


@app.route('/send-emails', methods=['POST'])
@limiter.limit(lambda: current_app.config['SEND_EMAIL_RATE_LIMIT'])
def send_emails():
    creds = get_credentials(require_redirect=False)
    if not creds:
        app.logger.error("Authentication failed in /send-emails endpoint (credentials missing or expired).")
        return jsonify({"success": False, "error": "Authentication required or expired. Please reload the page to sign in again.", "statusCode": 401}), 401

    try:
        service = build('gmail', 'v1', credentials=creds)
        sender_email = session.get('user_email')


        if not sender_email or '@' not in sender_email:
            try:
                profile = service.users().getProfile(userId='me').execute()
                sender_email = profile['emailAddress']
                session['user_email'] = sender_email
                app.logger.info(f"Re-fetched sender email for sending: {sender_email}")
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


    max_attachments = current_app.config['MAX_ATTACHMENTS_PER_EMAIL']
    if len(attachments) > max_attachments:
         return jsonify({"success": False, "error": f"Too many attachments. Maximum allowed is {max_attachments}.", "statusCode": 400}), 400

    total_attachment_size = 0
    valid_attachments = []
    for file_storage in attachments:
        if file_storage and file_storage.filename:
             try:

                current_pos = file_storage.tell()
                file_storage.seek(0, os.SEEK_END)
                size = file_storage.tell()
                file_storage.seek(current_pos)

                if size == 0 and file_storage.content_length is not None and file_storage.content_length > 0:
                    size = file_storage.content_length
                    app.logger.warning(f"Used content_length {size} for {file_storage.filename} as seek returned 0")

                if size > 0:
                    total_attachment_size += size
                    valid_attachments.append(file_storage)
                else:
                    app.logger.warning(f"Skipping empty attachment: {file_storage.filename}")

             except Exception as e:
                 app.logger.warning(f"Could not get size for attachment {file_storage.filename}: {e}. Skipping.")
        elif file_storage:
            app.logger.warning(f"Skipping attachment with no filename.")


    max_total_size_bytes = current_app.config['MAX_TOTAL_ATTACHMENT_SIZE_MB'] * 1024 * 1024
    if total_attachment_size > max_total_size_bytes:
        max_total_size_mb = app.config['MAX_TOTAL_ATTACHMENT_SIZE_MB']
        return jsonify({"success": False, "error": f"Total attachment size exceeds limit ({max_total_size_mb} MB). Calculated size: {total_attachment_size / (1024*1024):.2f} MB", "statusCode": 400}), 400

    attachments_to_use = valid_attachments


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
            except MemoryError:
                 app.logger.error("Attempted to process a CSV file that is too large.")
                 return jsonify({"success": False, "error": "CSV file is too large to process in memory. Please reduce its size."}), 400
            except UnicodeDecodeError:
                 app.logger.error("CSV file is not valid UTF-8.")
                 return jsonify({"success": False, "error": "Could not decode CSV file. Please ensure it is UTF-8 encoded."}), 400
            except Exception as e:
                app.logger.error(f"Error processing CSV file: {e}")
                return jsonify({"success": False, "error": f"Error reading or parsing CSV file: {e}. Ensure it's a valid UTF-8 encoded CSV with headers."}), 400

            max_csv_recipients = app.config['MAX_CSV_RECIPIENTS']
            if len(df) > max_csv_recipients:
                 app.logger.warning(f"CSV file has {len(df)} rows, exceeding the limit of {max_csv_recipients}. Truncating.")
                 df = df.head(max_csv_recipients)

                 results.append({"row": "N/A", "status": "warning", "reason": f"CSV file exceeded the maximum row limit ({max_csv_recipients}). Only the first {max_csv_recipients} rows were processed.", "recipient": "N/A"})


            for index, row in df.iterrows():

                try:
                    recipient_email_raw = str(row.get(recipient_template.strip('{}'), '')).strip()
                except KeyError:
                     results.append({"row": index + 2, "status": "skipped", "reason": f"Recipient template column '{recipient_template.strip('{}')}' not found in CSV.", "recipient": "N/A"})
                     continue

                total_recipients += 1
                recipient_email = recipient_email_raw

                if not is_valid_email(recipient_email):
                    results.append({"row": index + 2, "status": "skipped", "reason": "Invalid email address format", "recipient": recipient_email})
                    continue


                personalized_subject = subject_template
                personalized_body = body_template
                for header in df.columns:
                    placeholder = "{" + header + "}"
                    value = str(row.get(header, ''))
                    personalized_subject = personalized_subject.replace(placeholder, value)
                    personalized_body = personalized_body.replace(placeholder, value)


                message = create_message(sender_email, recipient_email, personalized_subject, personalized_body, attachments_to_use)
                try:
                    send_gmail_message(service, 'me', message)
                    results.append({"row": index + 2, "status": "sent", "recipient": recipient_email})
                except HttpError as send_err:
                    results.append({"row": index + 2, "status": "failed", "reason": f"Gmail API error: {send_err.resp.status} - {send_err.content}", "recipient": recipient_email})
                except Exception as e:
                    results.append({"row": index + 2, "status": "failed", "reason": f"Unexpected error during send: {e}", "recipient": recipient_email})


        elif mode == 'manual':
            manual_recipients_raw = request.form.get('manual_recipients', '')
            if not manual_recipients_raw:
                 return jsonify({"success": False, "error": "At least one recipient is required for manual mode."}), 400

            recipients = [email.strip() for email in re.split(r'[,\s]+', manual_recipients_raw) if email.strip()]

            if len(recipients) > app.config['MAX_MANUAL_RECIPIENTS']:
                return jsonify({"success": False, "error": f"Number of recipients exceeds the maximum allowed ({app.config['MAX_MANUAL_RECIPIENTS']})."}), 400

            for recipient_email in recipients:
                total_recipients += 1
                if not is_valid_email(recipient_email):
                    results.append({"row": total_recipients, "status": "skipped", "reason": "Invalid email address format", "recipient": recipient_email})
                    continue


                message = create_message(sender_email, recipient_email, subject_template, body_template, attachments_to_use)
                try:
                    send_gmail_message(service, 'me', message)
                    results.append({"row": total_recipients, "status": "sent", "recipient": recipient_email})
                except HttpError as send_err:
                     results.append({"row": total_recipients, "status": "failed", "reason": f"Gmail API error: {send_err.resp.status} - {send_err.content}", "recipient": recipient_email})
                except Exception as e:
                     results.append({"row": total_recipients, "status": "failed", "reason": f"Unexpected error during send: {e}", "recipient": recipient_email})

        else:
            return jsonify({"success": False, "error": "Invalid mode specified."}), 400



        success_count = sum(1 for r in results if r['status'] == 'sent')
        skipped_count = sum(1 for r in results if r['status'] == 'skipped')
        failed_count = sum(1 for r in results if r['status'] == 'failed')
        warning_count = sum(1 for r in results if r['status'] == 'warning')

        summary_message = f"Process completed ({mode} mode). Target(s): {total_recipients}."
        if warning_count > 0:
             summary_message += f" Warnings: {warning_count}."
        summary_message += f" Sent: {success_count}, Skipped: {skipped_count}, Failed: {failed_count}."

        app.logger.info(summary_message)
        return jsonify({"success": True, "message": summary_message, "results": results})

    except pd.errors.EmptyDataError:
        app.logger.error("Attempted to process an empty or invalid CSV file.")
        return jsonify({"success": False, "error": "CSV file is empty or invalid."}), 400
    except Exception as e:

        app.logger.error(f"A critical error occurred in /send-emails: {e}", exc_info=True)
        return jsonify({"success": False, "error": f"An unexpected server error occurred: {str(e)}"}), 500

@app.route('/logout')
def logout():
    session.pop('credentials', None)
    session.pop('user_email', None)
    session.pop('oauth_state', None) # Clear any pending states too
    app.logger.info("User logged out, session cleared.")
    return redirect(url_for('index'))

def create_message(sender, to, subject, body_html, attachments=None):
    message = MIMEMultipart('related')
    message['to'] = to

if __name__ == '__main__':
    is_configured = bool(CLIENT_CONFIG or os.path.exists(CREDENTIALS_PATH))
    if not is_configured:
        print("\nERROR: Google API credentials are not configured correctly.", file=sys.stderr)
        print("Please set the GOOGLE_CREDENTIALS_JSON environment variable or place a valid credentials.json file in the root directory.", file=sys.stderr)
        sys.exit(1)

    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't'] # Default Debug to False for production safety

    print(f"Starting Flask app on {host}:{port} (Debug: {debug_mode})")
    # Only warn about insecure transport if actually set (should NOT be in production)
    if os.environ.get('OAUTHLIB_INSECURE_TRANSPORT') == '1':
        print("WARNING: OAUTHLIB_INSECURE_TRANSPORT is set. OAuth HTTP is allowed (local development ONLY).")
    print(f"Limits: CSV Rows={app.config['MAX_CSV_RECIPIENTS']}, Manual Emails={app.config['MAX_MANUAL_RECIPIENTS']}, Attachments={app.config['MAX_ATTACHMENTS_PER_EMAIL']}, Total Attach Size={app.config['MAX_TOTAL_ATTACHMENT_SIZE_MB']}MB")
    print(f"Rate Limits: Endpoint={app.config['SEND_EMAIL_RATE_LIMIT']}, Global={app.config['GLOBAL_RATE_LIMIT_HOUR']} (hour), {app.config['GLOBAL_RATE_LIMIT_DAY']} (day)")

    app.run(host=host, port=port, debug=debug_mode)