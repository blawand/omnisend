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
            try:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
                
                creds = flow.run_local_server(port=0, prompt='consent',
                                             authorization_prompt_message='Please authorize this application to send emails on your behalf:')
                app.logger.info("New authorization successful.")
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
                
                part = MIMEBase(main_type, sub_type)
                file_content = file_storage.read()
                part.set_payload(file_content)
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment', filename=file_storage.filename)
                message.attach(part)
                file_storage.seek(0) 
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

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/send-emails', methods=['POST'])
def send_emails():
    creds = get_credentials()
    if not creds:
        app.logger.error("Authentication failed in /send-emails endpoint.")
        return jsonify({"success": False, "error": "Authentication failed. Could not get credentials. Please try reloading the page or check server logs."}), 401

    try:
        recipient_template = request.form.get('recipient_template')
        subject_template = request.form.get('subject_template')
        body_template = request.form.get('body_template')
        csv_file = request.files.get('csv_file')
        attachments = request.files.getlist('attachments')

        if not csv_file:
            return jsonify({"success": False, "error": "CSV file is required."}), 400
        if not recipient_template or not subject_template or not body_template:
             return jsonify({"success": False, "error": "Recipient, Subject, and Body templates are required."}), 400

        try:
            csv_content = csv_file.read().decode('utf-8-sig') 
            df = pd.read_csv(io.StringIO(csv_content), dtype=str) 
            df = df.fillna('') 
            df.columns = [col.strip() for col in df.columns] 
        except Exception as e:
             app.logger.error(f"Error processing CSV file: {e}")
             return jsonify({"success": False, "error": f"Error reading or parsing CSV file: {e}. Ensure it's a valid UTF-8 encoded CSV."}), 400


        if df.empty:
             return jsonify({"success": False, "error": "CSV file is empty or contains only headers."}), 400


        try:
            service = build('gmail', 'v1', credentials=creds)
            profile = service.users().getProfile(userId='me').execute()
            sender_email = profile['emailAddress']
            app.logger.info(f"Authenticated as {sender_email}")
        except HttpError as e:
             app.logger.error(f"Failed to get Gmail profile: {e}")
             # Check if it's an auth error (e.g., token revoked)
             if e.resp.status == 401 or e.resp.status == 403:
                 if os.path.exists(TOKEN_PATH):
                     os.remove(TOKEN_PATH)
                 return jsonify({"success": False, "error": f"Gmail authentication error ({e.resp.status}). Please reload the page and re-authenticate."}), 401
             return jsonify({"success": False, "error": f"Failed to connect to Gmail service: {e}"}), 500
        except Exception as e:
             app.logger.error(f"Unexpected error building Gmail service: {e}")
             return jsonify({"success": False, "error": f"Unexpected error connecting to Gmail: {e}"}), 500

        results = []
        total_rows = len(df)
        app.logger.info(f"Starting email sending process for {total_rows} rows.")

        for index, row in df.iterrows():
            row_num = index + 1 
            try:
                recipient = recipient_template
                subject = subject_template
                body = body_template

                for col in df.columns:
                    placeholder = f'{{{col}}}'
                    
                    value = str(row[col]) if pd.notna(row[col]) else ''
                    
                    recipient = recipient.replace(placeholder, value)
                    subject = subject.replace(placeholder, value)
                    body = body.replace(placeholder, value)

                recipient = recipient.strip()
                if '@' not in recipient or ' ' in recipient:
                    results.append({"row": row_num, "status": "skipped", "reason": "Invalid recipient email format", "recipient": recipient})
                    app.logger.warning(f"Skipping row {row_num}: Invalid recipient email '{recipient}'")
                    continue

                
                missing_placeholders = []
                for template_field in [recipient, subject, body]:
                     placeholders_found = pd.Series(template_field).str.findall(r'\{.*?\}').explode().unique()
                     for ph in placeholders_found:
                         if ph.strip('{}') not in df.columns:
                             missing_placeholders.append(ph)
                
                if missing_placeholders:
                    unique_missing = list(set(missing_placeholders))
                    reason = f"Unresolved placeholders found: {', '.join(unique_missing)}. Check spelling/case against CSV headers."
                    results.append({"row": row_num, "status": "skipped", "reason": reason , "recipient": recipient})
                    app.logger.warning(f"Skipping row {row_num} for {recipient}: {reason}")
                    continue


                app.logger.info(f"Attempting to send email to: {recipient} (Row {row_num})")
                email_message = create_message(sender_email, recipient, subject, body, attachments)
                send_gmail_message(service, 'me', email_message)
                results.append({"row": row_num, "status": "sent", "recipient": recipient})

            except HttpError as http_err:
                error_details = str(http_err)
                reason = f"Gmail API Error: {error_details}"
                results.append({"row": row_num, "status": "failed", "reason": reason, "recipient": recipient})
                app.logger.error(f"Failed sending to {recipient} (row {row_num}): {reason}")
            
            except Exception as e:
                error_details = str(e)
                reason = f"Unexpected Error: {error_details}"
                results.append({"row": row_num, "status": "failed", "reason": reason, "recipient": recipient})
                app.logger.error(f"Unexpected error sending to {recipient} (row {row_num}): {reason}")
                import traceback
                traceback.print_exc()


        success_count = sum(1 for r in results if r['status'] == 'sent')
        skipped_count = sum(1 for r in results if r['status'] == 'skipped')
        failed_count = sum(1 for r in results if r['status'] == 'failed')
        summary_message = f"Email sending process completed. Sent: {success_count}, Skipped: {skipped_count}, Failed: {failed_count} out of {total_rows} total rows."
        app.logger.info(summary_message)

        return jsonify({"success": True, "message": summary_message, "results": results})

    except pd.errors.EmptyDataError:
        app.logger.error("Attempted to process an empty or invalid CSV file.")
        return jsonify({"success": False, "error": "CSV file is empty or invalid."}), 400
    except Exception as e:
        app.logger.error(f"An critical error occurred in /send-emails: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": f"An unexpected server error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    
    app.run(debug=True, port=5000)