import os, sqlite3, uuid, math, qrcode, bcrypt

from collections import defaultdict
from flask import Blueprint, Flask, flash, redirect, render_template, request, session, g, url_for, jsonify, send_file, abort, current_app
from flask_session import Session
from werkzeug.user_agent import UserAgent
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError
from email.mime.text import MIMEText

from time import time, ctime
from datetime import datetime

from PIL import Image
from io import BytesIO
from geopy.geocoders import Nominatim

from rehomr.auth import login_required, allowed_file, valid_email, generate_verification_token, send_verification_email, generate_qr_code
from rehomr.db import get_db, init_db

bp = Blueprint('rehomr', __name__, static_url_path='/static/uploads')


@bp.route('/', methods=["GET"])
def index():
    db = get_db()
    if request.method == "GET":
        return render_template('index.html')


@bp.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            error = {'error': 'User not found'}
            return jsonify(error), 400
        password = request.form.get("password")
        pw_confirmation = request.form.get("confirmation")
        email_address = request.form.get("email")
        email_confirmation = request.form.get("email-conf")

        # NOTE: Always normalise an email address before checking if an address is in database
        if email_address and email_address == email_confirmation:
            try:
                tmp_email = valid_email(email_address, check_deliverability=True)
                email_address = tmp_email
                email_validity = True
            except EmailNotValidError as e:
                error = (str(e))
                error = {'Error': error}
                return jsonify(error, 503)
        email_validity = True
        if password and password == pw_confirmation and email_validity:
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            hashed_email = bcrypt.hashpw(email_address.encode('utf-8'), bcrypt.gensalt())
            try:
                db = get_db()
                user_exists = db.execute("SELECT * FROM users WHERE username = ? OR email_hash = ?", (username, hashed_email,)).fetchone()
                if user_exists:
                    error = {'error': 'Username is already taken. Please choose another.'}
                    return jsonify(error), 400
                else:
                    verification_token = generate_verification_token()
                    verification = send_verification_email(email_address, verification_token)
                    if not verification:
                        error = {'error': 'An error occurred while sending a verification email. Ensure you entered your email address correctly and try again.'}
                        return jsonify(error), 503
                    else:
                        db = get_db()
                        db.execute("INSERT INTO users (username, pw_hash, email_hash, verification_token, active) VALUES(?, ?, ?, ?, ?)", (username, hashed_pw, hashed_email, verification_token, 0))
                        db.commit()
                        db.close()
            except sqlite3.IntegrityError as e:
                db.rollback()
                db.close()
                error = {'error': 'An error occured while registering. Please try again.', 'sql_error': str(e)}
                return jsonify(error), 400
        else:
            error = {'error': 'Your request could not be completed. Ensure that you entered a unique username, valid password and matching confirmation.'}
            return jsonify(error), 400
    return redirect("/login")


@bp.route('/verify_email/<token>', methods=["GET"])
def verify_email(token):
    if request.method == "GET":
        try:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE verification_token = ?", (token,)).fetchone()
            if user:
                db.execute("UPDATE users SET active = 1 WHERE id = ?", (user['id'],))
                db.commit()
                db.close()
                flash("Your email has been verified! You may now log in.")
            else:
                flash('Invalid verification token. Please check your email and try again.', 'error')
                return redirect("/verify")
        except Exception as e:
            bp.logger.error(str(e))
            flash('An error occurred while verifying your email. Please try again later.', 'error')
            return redirect("/register")
        return render_template("verify_email.html")

        
@bp.route('/login', methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            error = 'You must provide a username and password'
            return jsonify(error), 400
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user['active'] < 1:
            error = 'Check your email inbox for an email from us with a verification link. Verify to log in.'
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
                return jsonify(error), 400
        return redirect("/")
    else:
        return render_template("login.html")


@bp.route('/logout')
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")


@bp.route('/username', methods=["GET", "POST"])
@login_required
def username():
    if request.method == "GET":
        return render_template('username.html')
    elif request.method == "POST":
        value = request.form.get("value")
        confirmation = request.form.get("confirmation")
        if not value or not confirmation or value != confirmation:
            error = 'Please fill out both fields with matching values'
            return jsonify(error, 403)
        else:
            try:
                db = get_db()
                db.execute("UPDATE users SET username = ? WHERE id = ?", (value, session["user_id"]))
                db.commit()
                db.close()
            except sqlite3.IntegrityError as e:
                flash(e)
                db.rollback()
            return redirect("/")


@bp.route('/password', methods=["GET", "POST"])
@login_required
def password():
    if request.method == "GET":
        return render_template('password.html')
    elif request.method == "POST":
        password = request.form.get("value")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation or password != confirmation:
            error = 'Please fill out both fields with matching values'
            flash(error)
            return jsonify(error, 403)
        else:
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            try:
                db = get_db()
                db.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (hashed_pw, session["user_id"]))
                db.commit()
                db.close()
            except sqlite3.IntegrityError as e:
                flash(e)
                db.rollback()
                db.close()
        return redirect("/login")


@bp.route('/email', methods=["GET", "POST"])
@login_required
def email():
    # This function receives as user input  a new email address they would like to swap for their old one.
    if request.method == "GET":
        return render_template('email.html')
    elif request.method == "POST":
        tmp_email = request.form.get("value")
        confirmation = request.form.get("confirmation")

        # NOTE: Always normalise an email address before checking if an address is in database (valid_email is trusted to return a normalised, valid, deliverable address or the excepted error)
        if tmp_email and tmp_email == confirmation:
            try:
                new_email = valid_email(tmp_email, check_deliverability=True)
                email_validity = True
            except EmailNotValidError as e:
                error = (str(e))
                error = {'Error': error}
                return jsonify(error, 503)
            try:
                db = get_db()
                old_email_hash = db.execute("SELECT email_hash FROM users WHERE id = ?", (session["user_id"],)).fetchone()
                if old_email_hash:
                    tmp_old_email = old_email_hash[0]
                    salt = tmp_old_email[:29] # extract the salt from the stored hash
                    new_email_hash = bcrypt.hashpw(new_email.encode('utf-8'), salt) # hash the new email with the extracted salt
                    if bcrypt.checkpw(new_email.encode('utf-8'), tmp_old_email): # compare the new hash with the stored hash
                        error = 'The email address you entered is the same as the one in our database. If the error persists, please contact us.'
                        return jsonify(error, 403)
                    else:
                        verification_token = generate_verification_token()
                        verification = send_verification_email(new_email, verification_token)
                        if not verification:
                            error = {'error': 'An error occurred while sending a verification email. Ensure you entered your email address correctly and try again.'}
                            return jsonify(error), 503
                        db.execute("UPDATE users SET email_hash = ?, verification_token = ?, active = ? WHERE id = ?", (new_email_hash, verification_token, 0, session["user_id"]))
                        db.commit()
                        db.close()
            except sqlite3.IntegrityError as e:
                flash(e)
                db.rollback()
                db.close()
            return redirect("/")
        else:
            error = 'Please fill out both fields with matching values'
            return jsonify(error, 403)


@bp.route('/newstray', methods=["GET", "POST"])
def newstray():
    app = Flask(__name__)

    if request.method == "POST":
        # Get information on stray from user
        species = request.form.get("species")
        breed = request.form.get("breed")
        color = request.form.get("color")
        city = request.form.get("city")
        state = request.form.get("state")
        desc = request.form.get("description")
        stray_add_time = time()
        # Generate unique ID for stray
        imageid = str(uuid.uuid4())
        # Get image, check filesize, 
        if 'image' in request.files:
            file = request.files['image']
            max_size = 4 * 1024 * 1024 # 4MB
            if len(file.read()) > max_size:
                flash("File size exceeds 4MB limit")
                return redirect('/')
            file.seek(0) # rewind file pointer
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # rename file to unique ID and save to designated directory
                file.seek(0)
                file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], imageid + '.' + filename.rsplit('.', 1)[1]))
                file.close()
            else:
                flash("Invalid file type. Allowed file types are: jpg, jpeg, gif, and png")
                return redirect('/')
        try:
            db = get_db()
            db.execute("INSERT INTO strays (species, breed, color, city, state, description, image_id, time, user_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", (species, breed, color, city, state, desc, imageid, stray_add_time, session["user_id"]))
            db.commit()
            db.close()
        except sqlite3.IntegrityError as e:
            flash(e)
            db.rollback()
            db.close()
        return redirect('/strays')
            
    if request.method == "GET":
        # Check if user is using mobile, get geo-location to pre-populate city/state fields
        user_agent = UserAgent(request.headers.get('User-Agent'))
        is_mobile = user_agent.platform in ('android', 'iphone')
        if is_mobile:
            geolocator = Nominatim(user_agent='rehomr')
            user_ip = request.remote_addr
            location = geolocator.geocode(user_ip, language='en', timeout=10)
            city = location.raw.get('address', {}).get('city', '')
            state = location.raw.get('address', {}).get('state', '')
            location = jsonify({'city': city, 'state': state})
            return render_template('newstray.html', location=location)
        else:
            return render_template('newstray.html')
    

@bp.route('/strays', methods=["GET"])
def strays():
    if request.method == "GET":
        results_per_page = 10
        # Get current page number from query parameter
        page = request.args.get('page', 1, type=int)
        # Calculate offset and limit values for pagination
        offset = (page - 1) * results_per_page
        limit = offset + results_per_page
        db = get_db()
        strays = db.execute("SELECT * FROM strays ORDER BY id LIMIT ? OFFSET ?", (results_per_page, offset))
        strays_dict = {stray['id']: dict(stray) for stray in strays}
        strays_list = [dict(strays_dict[key], id=key) for key in strays_dict]
        new_strays_list = []
        for stray in strays_list:
            # Generate the image URL using the image_id
            path = get_image(stray['image_id'])
            if path is None:
                image_url = url_for('static', filename='uploads/' + 'placeholder.jpg')
            else:
                thumb_path = thumbnail(path)
                image_url = url_for('static', filename='uploads/thumbnails/' + thumb_path)
            # Generate url to house stray
            stray_url = url_for('rehomr.stray', stray_id=stray['id'])
            new_strays_list.append({
                'id': stray['id'],
                'species': stray['species'],
                'breed': stray['breed'],
                'color': stray['color'],
                'city': stray['city'],
                'state': stray['state'],
                'image_url': image_url,
                'stray_url': stray_url
            })
        
        total_pages = math.ceil(db.execute("SELECT COUNT(*) FROM strays").fetchone()[0])
        num_pages = math.ceil(total_pages / results_per_page)
        strays.close()
        if page < 1 or page > num_pages:
            abort(404)
        context = {'page': page, 'total_pages': total_pages, 'num_pages': num_pages}
        return render_template('strays.html', strays=new_strays_list, context=context)


@bp.route("/about", methods=["GET"])
def about():
    if request.method == "GET":
        return render_template("about.html")
    else:
        return redirect("/")


@bp.route("/survey", methods=["GET", "POST"])
@login_required
def survey():
    if request.method == "GET":
        return render_template("/survey.html")
    if request.method == "POST":
        with request:
            file_format = request.form.get("sel_format")
        if file_format:
            qr_code_filename = generate_qr_code(file_format)
            if qr_code_filename:
                return render_template("/download.html", filename=qr_code_filename)
            else:
                flash('An error occured in the "generate_qr_code" function')
                return redirect("/survey")
        else:
            return redirect("/")


@bp.route("/download/<file_path>", methods=["GET"])
def download(file_path):
    if request.method == "GET":
        file_name = os.path.basename(file_path)
        return render_template("/download.html", image_url=image_url)


@bp.route("/history", methods=["GET"])
@login_required
def history():
    """Show history of transactions"""

    if request.method == "GET":
        db = get_db()
        strays = db.execute("SELECT * FROM strays WHERE user_id = ?", (session["user_id"],))
        strays_dict = {stray['id']: dict(stray) for stray in strays}
        strays_list = [dict(strays_dict[key], id=key) for key in strays_dict]
        strays.close()
        new_strays_list = []
        for stray in strays_list:
            date = datetime.fromtimestamp(stray['time'])
            date = date.strftime('%Y-%m-%d %H:%M:%S')
            # Generate the image URL using the image_id
            path = get_image(stray['image_id'])
            if path is None:
                image_url = url_for('static', filename='uploads/' + 'placeholder.jpg')
            else:
                thumb_path = thumbnail(path)
                image_url = url_for('static', filename='uploads/thumbnails/' + thumb_path)
            # Generate url to house stray
            stray_url = url_for('rehomr.stray', stray_id=stray['id'])
            new_strays_list.append({
                'id': stray['id'],
                'species': stray['species'],
                'breed': stray['breed'],
                'color': stray['color'],
                'city': stray['city'],
                'state': stray['state'],
                'image_url': image_url,
                'stray_url': stray_url,
                'time': date
            })
        return render_template("history.html", strays=new_strays_list)


@bp.route('/stray/<int:stray_id>')
def stray(stray_id, methods=["GET"]):
    # Get the stray per id
    if request.method == "GET":
        db = get_db()
        cursor = db.execute("SELECT * FROM strays WHERE id = ?", (stray_id,))
        stray = cursor.fetchone()
        if stray is None:
            error = None
            cursor.close()
            conn.close()
            return error
        else:
            path = get_image(stray['image_id'])
            if path is None:
                image_url = url_for('static', filename='uploads/' + 'placeholder.jpg')
            else:
                image_extension = path.rsplit('.', 1)[1].lower()
                if image_extension in current_app.config['ALLOWED_EXTENSIONS']:
                    image_url = url_for('static', filename='uploads/' + path)
            stray_url = url_for('rehomr.strays', stray_id=stray['id'])
            new_info_dict = {
                'id': stray['id'],
                'species': stray['species'],
                'breed': stray['breed'],
                'color': stray['color'],
                'city': stray['city'],
                'state': stray['state'],
                'description': stray['description'],
                'image_url': image_url,
                'stray_url': stray_url
            }
            return render_template('stray.html', stray=new_info_dict)


@bp.route('/animal/<image_id>', methods=["GET"])
def get_image(image_id):
    db = get_db()
    cursor = db.execute("SELECT * FROM strays WHERE image_id = ?", (image_id,))
    animal = cursor.fetchone()
    if animal is None:
        error = None
        cursor.close()
        conn.close()
        return error
    filename = None
    for extension in current_app.config['ALLOWED_EXTENSIONS']:
        temp_filename = os.path.join(current_app.config['UPLOAD_FOLDER'], f'{animal["image_id"]}.{extension}')
        if os.path.isfile(temp_filename):
            filename = f'{animal["image_id"]}.{extension}'
            break
    if filename is None:
        error = None
        cursor.close()
        return error
    return filename


@bp.route('/thumbnail/<path:filename>')
def thumbnail(filename, size=(128, 128)):
    if not allowed_file(filename):
        raise ValueError(f"File extension not allowed: {filename}")
    base, ext = os.path.splitext(filename)
    thumb_filename = f"{base}_thumb{ext}"
    try:
        with Image.open(os.path.join(current_app.config['UPLOAD_FOLDER'], filename)) as im:
            im.thumbnail(size)
            im.save(os.path.join(current_app.config['UPLOAD_FOLDER'], 'thumbnails', thumb_filename))
    except OSError:
        print(f"Cannot create thumbnail for {filename}")
    return thumb_filename