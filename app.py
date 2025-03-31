from flask import Flask, request, render_template
import pandas as pd
import os
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

app = Flask(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_credentials():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def send_email(creds, to, subject, body, attachments):
    service = build('gmail', 'v1', credentials=creds)
    
    msg = MIMEMultipart()
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    
    # Attach any files
    for attachment in attachments:
        with open(attachment, "rb") as f:
            attach = MIMEApplication(f.read(), _subtype="pdf")
            attach.add_header('Content-Disposition', 'attachment', filename=os.path.basename(attachment))
            msg.attach(attach)

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    message = {'raw': raw}
    service.users().messages().send(userId="me", body=message).execute()

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_emails():
    recipient_template = request.form['recipient_email']
    subject_template = request.form['subject']
    body_template = request.form['template']
    csv_file = request.files['csv_file']
    df = pd.read_csv(csv_file)
    
    creds = get_credentials()

    # Handle file attachments
    attachments = []
    for file in request.files.getlist("attachments"):
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        attachments.append(file_path)
    
    for _, row in df.iterrows():
        recipient = recipient_template
        subject = subject_template
        body = body_template

        for col in df.columns:
            recipient = recipient.replace(f'{{{col}}}', str(row[col]))
            subject = subject.replace(f'{{{col}}}', str(row[col]))
            body = body.replace(f'{{{col}}}', str(row[col]))

        # Validate email address (basic validation)
        if '@' not in recipient:
            continue  # Skip sending this email if the recipient email is invalid

        send_email(creds, recipient, subject, body, attachments)
    
    return 'Emails have been generated and sent!'

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)