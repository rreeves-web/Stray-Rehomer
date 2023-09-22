from __future__ import print_function
import functools, secrets, string, smtplib, base64, os, qrcode, io, slimta, bcrypt


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
           

def validate_registration(username, password, password_confirmation, email, email_confirmation):
    # NOTE: Always normalise an email address before checking if an address is in database
    if email and email == email_confirmation:
        try:
            tmp_email = valid_email(email, check_deliverability=True)
            email = tmp_email
            email_validity = True
        except EmailNotValidError as e:
            error = {'error': str(e)}
            return jsonify(error, status=400)

    if password and password == password_confirmation and email_validity:
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_email = bcrypt.hashpw(email.encode('utf-8'), bcrypt.gensalt())
        try:
            db = get_db()
            user_exists = db.execute("SELECT * FROM users WHERE username = ? OR email_hash = ?", (username, hashed_email,)).fetchone()
            if user_exists:
                error = {'error': 'Username is already taken. Please choose another.'}
                return jsonify(error, status=401)
            else:
                db = get_db()
                db.execute("INSERT INTO users (username, pw_hash, email_hash, active) VALUES(?, ?, ?, ?)", (username, hashed_pw, hashed_email, 0))
                db.commit()
                db.close()
                # This code implements verification tokens sent by email, but my google admin
                # trial expired, so I've removed this functionality for now. If I implement
                # my own email server then I'll re-implement this.
                """verification_token = generate_verification_token()
                verification = send_verification_email(email, verification_token)
                if not verification:
                    error = {'error': 'An error occurred while sending a verification email. Ensure you entered your email address correctly and try again.'}
                    return jsonify(error, status=503)
                else:
                    db = get_db()
                    db.execute("INSERT INTO users (username, pw_hash, email_hash, verification_token, active) VALUES(?, ?, ?, ?, ?)", (username, hashed_pw, hashed_email, verification_token, 0))
                    db.commit()
                    db.close()"""
        except sqlite3.IntegrityError as e:
            db.rollback()
            db.close()
            error = {'error': 'An error occured while registering. Please try again.', 'sql_error': str(e)}
            return jsonify(error, status=400)
    else:
        error = {'error': 'Your request could not be completed. Ensure that you entered a unique username, valid password and matching confirmation.'}
        return jsonify(error, status=401)


def valid_email(address, check_deliverability=False):
    if check_deliverability:
        try:
            # Check that the email address is valid. Turn on check_deliverability
            # for first-time validations like on account creation pages (but not
            # login pages).
            emailinfo = validate_email(address, check_deliverability=True)

            # Use only the normalized form of the email address, especially before going to a database query.
            email = emailinfo.normalized
            return email

        except EmailNotValidError as e:
            error = {'error': str(e)}
            return jsonify(error, status=400)
    else:
        try:
            emailinfo = validate_email(address, check_deliverability=False)
            email = emailinfo.normalized
            return email
        except EmailNotValidError as e:
            error = {'error': str(e)}
            return jsonify(error, status=400)

def validate_login(username, password):
    if not username or not password:
        error = 'You must provide a username and password'
        return jsonify(error, status=401)
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user['active'] < 1:
        error = 'Check your email inbox for a message from us with a verification link. Verify to log in.'
        flash(error)
        return redirect("/")

    db_password_hash = db.execute("SELECT pw_hash FROM users WHERE username = ?", (username,)).fetchone()
    if user and db_password_hash:
        tmp_var = db_password_hash[0]
        salt = tmp_var[:29]
        new_password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        if bcrypt.checkpw(password.encode('utf-8'), db_password_hash[0]):
            session["user_id"] = user["id"]
            db.close()
            return redirect("/")
        else:
            error = 'Password is incorrect'
            return jsonify(error, status=400)
    return redirect("/")

def validate_username_change(username, confirmation):

    if not username or not confirmation or username != confirmation:
        error = 'Please fill out both fields with matching values'
        raise ValueError(error)
    try:
        db = get_db()
        db.execute("UPDATE users SET username = ? WHERE id = ?", (username, session["user_id"]))
        db.commit()
        db.close()
    except sqlite3.IntegrityError as e:
        flash(e)
        db.rollback()
        db.close()
    return redirect("/")

# Generate a random string for email verification token
def generate_verification_token(length=32):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

 
def send_verification_email(email, verification_token):

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
        message = create_message(os.environ.get('EMAIL'), email, subject, body)
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
