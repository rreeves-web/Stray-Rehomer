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


"""@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')"""


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        elif user['active'] == 0:
            error = 'Unverified email address.'
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('login.html')


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

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


"""@bp.route('/verify/<token>', methods=["GET"])
def verify_email(token):
    if method == "GET":
        try:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE verification_token = ?", (token,)).fetchone()
            if user:
                db.execute("UPDATE users SET active = 1 WHERE id = ?", (user['id'],))
                db.commit()
                db.close()
                flash('Your email has been verified!', 'success')
                return redirect("/login")
            else:
                flash('Invalid verification token. Please check your email and try again.', 'error')
                return redirect("/register")
        except Exception as e:
            bp.logger.error(str(e))
            flash('An error occurred while verifying your email. Please try again later.', 'error')
            return redirect("/register")"""

 
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
    d.text((10, 10), "Help re-home stray cats and dogs! Scan this to begin!", fill=(0,))

    file_name = 'strays_qr_code.' + user_format
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_name)

    # Save the image to a BytesIO object
    img.save(file_path, user_format)

    # Return only the file name
    return file_name


def create_message(sender, to, subject, body):
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    message['from'] = sender
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': encoded_message}


def send_message(service, user_id, message):
    try:
        message = (service.users().messages().send(userId=user_id, body=message).execute())
    except HttpError as error:
        print('An error occurred: %s' % error)
        message = None
    return message
