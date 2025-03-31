from flask import Flask, request, render_template, jsonify
import pandas as pd
import io
import os
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import mimetypes
import logging
import re

app = Flask(__name__)
app.secret_key = os.urandom(24) 

logging.basicConfig(level=logging.INFO)

SCOPES = ['https://www.googleapis.com/auth/gmail.send']
TOKEN_PATH = 'token.json'
CREDENTIALS_PATH = 'credentials.json'

def get_credentials():
    creds = None
    if os.path.exists(TOKEN_PATH):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
        except Exception as e:
            app.logger.error(f"Error loading token file: {e}. Deleting invalid token.")
            if os.path.exists(TOKEN_PATH):
                os.remove(TOKEN_PATH)
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                app.logger.info("Token refreshed successfully.")
            except Exception as e:
                app.logger.error(f"Error refreshing token: {e}. Token might be revoked or invalid.")
                if os.path.exists(TOKEN_PATH):
                    os.remove(TOKEN_PATH)
                app.logger.info("Attempting new authorization flow.")
                creds = None 
        
        if not creds: 
            if not os.path.exists(CREDENTIALS_PATH):
                app.logger.error(f"Credentials file not found at {CREDENTIALS_PATH}")
                return None
            try:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
                creds = flow.run_local_server(port=0, prompt='consent',
                                             authorization_prompt_message='Please authorize this application to send emails on your behalf:')
                app.logger.info("New authorization successful.")
            except FileNotFoundError:
                 app.logger.error(f"Credentials file not found at {CREDENTIALS_PATH}")
                 return None
            except Exception as e:
                app.logger.error(f"Error during OAuth flow: {e}")
                return None
        
        if creds:
            try:
                with open(TOKEN_PATH, 'w') as token:
                    token.write(creds.to_json())
                app.logger.info("Token saved successfully.")
            except IOError as e:
                app.logger.error(f"Error writing token file: {e}")
                return None
    return creds

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
    return render_template('index.html')

@app.route('/send-emails', methods=['POST'])
def send_emails():
    creds = get_credentials()
    if not creds:
        app.logger.error("Authentication failed in /send-emails endpoint.")
        error_message = "Authentication failed. Could not get credentials."
        if not os.path.exists(CREDENTIALS_PATH):
            error_message += f" Missing credentials file ({CREDENTIALS_PATH}). Please ensure it exists."
        else:
             error_message += " Please try reloading the page to re-authenticate, or check server logs."
        return jsonify({"success": False, "error": error_message}), 401

    try:
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        sender_email = profile['emailAddress']
        app.logger.info(f"Authenticated as {sender_email}")
    except HttpError as e:
         app.logger.error(f"Failed to get Gmail profile: {e}")
         if e.resp.status == 401 or e.resp.status == 403:
             if os.path.exists(TOKEN_PATH):
                 os.remove(TOKEN_PATH)
             return jsonify({"success": False, "error": f"Gmail authentication error ({e.resp.status}). Please reload the page and re-authenticate."}), 401
         return jsonify({"success": False, "error": f"Failed to connect to Gmail service: {e}"}), 500
    except Exception as e:
         app.logger.error(f"Unexpected error building Gmail service: {e}")
         return jsonify({"success": False, "error": f"Unexpected error connecting to Gmail: {e}"}), 500

    mode = request.form.get('mode', 'csv') # Default to csv mode
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
        
        summary_message = f"Process completed for {total_recipients} target(s) ({mode} mode). Sent: {success_count}, Skipped: {skipped_count}, Failed: {failed_count}."
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
    app.run(debug=True, port=5000)