from __future__ import print_function
import functools, secrets, string, smtplib, base64, os, qrcode, io, slimta


from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify, send_from_directory, current_app, send_file
)
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from email_validator import validate_email, EmailNotValidError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.message import EmailMessage

from geopy.geocoders import Nominatim
from PIL import Image, ImageDraw
from rehomr.db import get_db

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


bp = Blueprint('auth', __name__, url_prefix='/auth', static_url_path='/static')
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
SCOPES = ['https://www.googleapis.com/auth/gmail.send']


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('rehomr.login'))

        return view(**kwargs)

    return wrapped_view


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[-1].lower() in ALLOWED_EXTENSIONS


def valid_email(address, check_deliverability=False):
    if check_deliverability:
        try:
            # Check that the email address is valid. Turn on check_deliverability
            # for first-time validations like on account creation pages (but not
            # login pages).
            emailinfo = validate_email(address, check_deliverability=True)

            # After this point, use only the normalized form of the email address,
            # especially before going to a database query.
            email = emailinfo.normalized
            return email

        except EmailNotValidError as e:

            # The exception message is human-readable explanation of why it's
            # not a valid (or deliverable) email address.
            print(str(e))
            return e
    else:
        try:
            emailinfo = validate_email(address, check_deliverability=False)
            email = emailinfo.normalized
            return email
        except EmailNotValidError as e:
            print(str(e))
            return e


# Generate a random string for email verification token
def generate_verification_token(length=32):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

 
def send_verification_email(email_address, verification_token):
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            credentials_path = os.path.join(os.getcwd(), 'credentials.json')
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        subject = 'Verification Email - Strays'
        verification_url = url_for('rehomr.verify_email', token=verification_token, _external=True)
        body = f'Thank you for registering with Strays. Please click the following link to verify your email address: {verification_url}'
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        message = create_message(os.environ.get('EMAIL_ADDRESS'), email_address, subject, body)
        send_message(service, 'strayanimalsfindhomes@gmail.com', message)
        if message:
            return True
        else:
            print(f'An error occured in the send_verification_email function')
            return None
    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred in the send_verification_email function: {error}')
        return None

def generate_qr_code(user_format):
    # Generate the QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data('https://straysplaceholder.url/')
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Add a brief summary to the image
    d = ImageDraw.Draw(img)
    d.text((10, 10), "Help re-home stray cats and dogs! Scan this to add a stray!", fill=(0,))
    
    db = get_db()
    cursor = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],))
    username = cursor.fetchone()[0]
    d.text((30, 345), "This QR code was generated by " + username, fill=(0,))

    file_name = 'strays_qr_code.' + user_format
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_name)

    # Save the image to a BytesIO object
    img.save(file_path, user_format)

    # Return only the file name
    if file_name and file_path:
        return file_name
    else:
        flash('An error occured in the "create_message" function')
        return None


def create_message(sender, to, subject, body):
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    message['from'] = sender
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    if encoded_message:
        return {'raw': encoded_message}
    else:
        flash('An error occured in the "create_message" function')
        return None


def send_message(service, user_id, message):
    try:
        message = (service.users().messages().send(userId=user_id, body=message).execute())
    except HttpError as error:
        flash('An error occurred in the "send_message" function: %s' % error)
        message = None
    return message
