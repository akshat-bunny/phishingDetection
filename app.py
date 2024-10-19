import os
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import pyodbc
import jwt
import logging

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'this_should_be_changed'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY') or 'another_secret_key'  # Secret key for JWT

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database connection using pyodbc
def get_db_connection():
    conn_str = (
        r'DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};'
        r'DBQ=' + os.path.join(os.getcwd(), 'database', 'users.accdb') + ';'
    )
    return pyodbc.connect(conn_str)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
    if user:
        return User(id=user.id, username=user.username, password=user.password)
    return None

# Registration Form
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username.data,))
            user = cursor.fetchone()
        if user:
            raise ValidationError("Username already exists. Please choose a different one.")

# Login Form
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# Phishing Detection Form
class DetectForm(FlaskForm):
    domain = StringField(validators=[InputRequired(),
                                      Length(min=4, max=255),
                                      Regexp(r'^(https?:\/\/)?(www\.)?([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$',
                                             message="Invalid domain format. Please enter a valid domain.")],
                         render_kw={"placeholder": "Enter domain"})
    submit = SubmitField("Check")

# Phishing Reporting Form
class ReportForm(FlaskForm):
    url = StringField(validators=[InputRequired(), Length(min=4, max=255)],
                      render_kw={"placeholder": "Enter phishing URL"})
    submit = SubmitField("Report Phishing")

# Define a custom filter to format UNIX timestamps
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    try:
        dt = datetime.utcfromtimestamp(int(value))
        return dt.strftime(format)
    except (ValueError, TypeError):
        return value

# Middleware for validating JWT
def validate_jwt():
    token = request.cookies.get('auth_token')
    if token:
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            return data['user_id']
        except jwt.ExpiredSignatureError:
            flash('Token has expired. Please log in again.', 'danger')
            return None
        except jwt.InvalidTokenError:
            flash('Invalid token. Please log in again.', 'danger')
            return None
    flash('Token not found. Please log in.', 'danger')
    return None

# Routes
@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                           (form.username.data, hashed_password))
            conn.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (form.username.data,))
            user = cursor.fetchone()
        if user and check_password_hash(user.password, form.password.data):
            user_obj = User(id=user.id, username=user.username, password=user.password)
            login_user(user_obj)

            # Create JWT token
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, app.config['JWT_SECRET_KEY'], algorithm="HS256")

            # Set the token in a cookie
            response = make_response(redirect(url_for('home')))
            response.set_cookie('auth_token', token, httponly=True, secure=True)  # Set httponly for security
            return response
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/detect', methods=['GET', 'POST'])
@login_required
def detect():
    form = DetectForm()
    result = None
    is_malicious = False
    malicious_votes = 0
    harmless_votes = 0

    if form.validate_on_submit():
        domain = form.domain.data.strip()
        logging.debug(f"Detecting domain: {domain}")

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                # Check if the domain already exists in the local database
                cursor.execute("SELECT * FROM phishing_reports WHERE url = ?", (domain,))
                existing_report = cursor.fetchone()

                if existing_report:
                    # If found, retrieve data from the local database
                    result = {
                        'url': existing_report.url,
                        'status': existing_report.status,
                        'checked_at': existing_report.checked_at,
                        'malicious_votes': existing_report.malicious_votes,
                        'harmless_votes': existing_report.harmless_votes,
                        'last_analysis_date': existing_report.last_analysis_date
                    }
                    is_malicious = existing_report.malicious_votes > 0
                    malicious_votes = existing_report.malicious_votes  # Update variable
                    harmless_votes = existing_report.harmless_votes  # Update variable
                    flash(f"The domain '{domain}' was found in the local database.", 'info')
                    logging.info(f"Domain found in local DB: {domain}")
                    logging.debug(f"Malicious Votes: {malicious_votes}, Harmless Votes: {harmless_votes}")
                else:
                    # Not found, fetch data from VirusTotal
                    vt_api_key = os.getenv('VT_API_KEY')
                    if not vt_api_key:
                        flash('VirusTotal API key not found. Please set VT_API_KEY in your .env file.', 'danger')
                        logging.error("VirusTotal API key not set.")
                        return render_template('detect.html', form=form, result=result, is_malicious=is_malicious)

                    headers = {
                        "Accept": "application/json",
                        "x-apikey": vt_api_key
                    }

                    vt_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
                    logging.debug(f"Making request to VirusTotal API: {vt_url}")
                    response = requests.get(vt_url, headers=headers)

                    if response.status_code == 200:
                        data = response.json()
                        try:
                            attributes = data['data']['attributes']
                            last_analysis_stats = attributes.get('last_analysis_stats', {})
                            malicious_votes = int(last_analysis_stats.get('malicious', 0))
                            harmless_votes = int(last_analysis_stats.get('harmless', 0))
                            is_malicious = malicious_votes > 0

                            # Convert UNIX timestamp to datetime
                            last_analysis_timestamp = attributes.get('last_analysis_date')
                            if last_analysis_timestamp:
                                last_analysis_date = datetime.utcfromtimestamp(last_analysis_timestamp)
                            else:
                                last_analysis_date = datetime.now()

                            result = {
                                'reputation': attributes.get('reputation'),
                                'last_analysis_date': last_analysis_date,
                                'last_analysis_stats': last_analysis_stats,
                            }

                            # Flash message based on the results
                            flash(f"The domain '{domain}' is found to be {'malicious' if is_malicious else 'safe'} according to VirusTotal.", 
                                  'danger' if is_malicious else 'success')
                            logging.info(f"Domain analyzed: {domain} - Malicious: {is_malicious}")

                            # Prepare datetime fields in string format for Access
                            checked_at_str = datetime.now().strftime('%m/%d/%Y %H:%M:%S')
                            last_analysis_date_str = last_analysis_date.strftime('%m/%d/%Y %H:%M:%S')

                            # Insert the fetched data into the phishing_reports table
                            cursor.execute(
                                "INSERT INTO phishing_reports (url, status, checked_at, malicious_votes, harmless_votes, last_analysis_date) VALUES (?, ?, ?, ?, ?, ?)",
                                (domain, 'checked', checked_at_str, malicious_votes, harmless_votes, last_analysis_date_str)
                            )
                            conn.commit()
                            logging.debug(f"Inserted data into phishing_reports for domain: {domain}")

                        except KeyError as e:
                            flash(f"Missing data in API response: {e}", 'danger')
                            logging.error(f"KeyError: Missing data {e} in API response for domain: {domain}")
                        except pyodbc.DataError as de:
                            flash(f"Data error: {de}", 'danger')
                            logging.error(f"DataError: {de} when inserting domain: {domain}")
                        except Exception as ex:
                            flash(f"An unexpected error occurred: {ex}", 'danger')
                            logging.error(f"Unexpected error: {ex} when processing domain: {domain}")
                    else:
                        if response.status_code == 404:
                            flash(f"Domain '{domain}' not found in VirusTotal database.", 'warning')
                            logging.warning(f"VirusTotal returned 404 for domain: {domain}")
                        elif response.status_code == 429:
                            flash('Rate limit exceeded. Try again later.', 'warning')
                            logging.warning("VirusTotal API rate limit exceeded.")
                        else:
                            flash(f'Error fetching data from VirusTotal: {response.status_code}', 'danger')
                            logging.error(f"VirusTotal API error {response.status_code} for domain: {domain}")

        except pyodbc.Error as db_err:
            flash(f"Database error: {db_err}", 'danger')
            logging.error(f"Database error during domain detection: {db_err}")

    return render_template('detect.html', form=form, result=result, is_malicious=is_malicious, 
                           malicious_votes=malicious_votes, harmless_votes=harmless_votes)

    form = DetectForm()
    result = None
    is_malicious = False
    malicious_votes = 0
    harmless_votes = 0

    if form.validate_on_submit():
        domain = form.domain.data.strip()

        with get_db_connection() as conn:
            cursor = conn.cursor()

            try:
                # Check if the domain already exists in the local database
                cursor.execute("SELECT * FROM phishing_reports WHERE url = ?", (domain,))
                existing_report = cursor.fetchone()

                if existing_report:
                    # If found, retrieve data from the local database
                    result = {
                        'url': existing_report.url,
                        'status': existing_report.status,
                        'checked_at': existing_report.checked_at,
                        'malicious_votes': existing_report.malicious_votes,
                        'harmless_votes': existing_report.harmless_votes,
                        'last_analysis_date': existing_report.last_analysis_date
                    }
                    is_malicious = existing_report.malicious_votes > 0
                    flash(f"The domain '{domain}' was found in the local database.", 'info')
                else:
                    # Not found, fetch data from VirusTotal
                    vt_api_key = os.getenv('VT_API_KEY')
                    if not vt_api_key:
                        flash('VirusTotal API key not found. Please set VT_API_KEY in your .env file.', 'danger')
                        return render_template('detect.html', form=form, result=result, is_malicious=is_malicious)

                    headers = {
                        "Accept": "application/json",
                        "x-apikey": vt_api_key
                    }

                    vt_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
                    response = requests.get(vt_url, headers=headers)

                    if response.status_code == 200:
                        data = response.json()
                        try:
                            attributes = data['data']['attributes']
                            last_analysis_stats = attributes.get('last_analysis_stats', {})
                            malicious_votes = int(last_analysis_stats.get('malicious', 0))
                            harmless_votes = int(last_analysis_stats.get('harmless', 0))
                            is_malicious = malicious_votes > 0

                            # Convert UNIX timestamp to datetime
                            last_analysis_timestamp = attributes.get('last_analysis_date')
                            if last_analysis_timestamp:
                                last_analysis_date = datetime.utcfromtimestamp(last_analysis_timestamp)
                            else:
                                last_analysis_date = datetime.now()

                            result = {
                                'reputation': attributes.get('reputation'),
                                'last_analysis_date': last_analysis_date,
                                'last_analysis_stats': last_analysis_stats,
                            }

                            # Flash message based on the results
                            flash(f"The domain '{domain}' is found to be {'malicious' if is_malicious else 'safe'} according to VirusTotal.", 
                                  'danger' if is_malicious else 'success')

                            # Insert the fetched data into the phishing_reports table
                            cursor.execute(
                                "INSERT INTO phishing_reports (url, status, checked_at, malicious_votes, harmless_votes, last_analysis_date) VALUES (?, ?, ?, ?, ?, ?)",
                                (domain, 'checked', datetime.now(), malicious_votes, harmless_votes, last_analysis_date)
                            )
                            conn.commit()

                        except KeyError as e:
                            flash(f"Missing data in API response: {e}", 'danger')
                        except pyodbc.DataError as de:
                            flash(f"Data error: {de}", 'danger')
                        except Exception as ex:
                            flash(f"An unexpected error occurred: {ex}", 'danger')
                    else:
                        if response.status_code == 404:
                            flash(f"Domain '{domain}' not found in VirusTotal database.", 'warning')
                        elif response.status_code == 429:
                            flash('Rate limit exceeded. Try again later.', 'warning')
                        else:
                            flash(f'Error fetching data from VirusTotal: {response.status_code}', 'danger')

            except pyodbc.Error as db_err:
                flash(f"Database error: {db_err}", 'danger')

    return render_template('detect.html', form=form, result=result, is_malicious=is_malicious, 
                           malicious_votes=malicious_votes, harmless_votes=harmless_votes)

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    form = ReportForm()
    if form.validate_on_submit():
        url = form.url.data.strip()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current date and time
        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                # Check if the URL is already reported
                cursor.execute("SELECT * FROM phishing_reports WHERE url = ?", (url,))
                existing_report = cursor.fetchone()

                if existing_report:
                    # If the URL has already been reported, increment the malicious_votes count
                    cursor.execute("""
                        UPDATE phishing_reports 
                        SET malicious_votes = malicious_votes + 1, 
                            status = ?, 
                            checked_at = ?, 
                            last_analysis_date = ?
                        WHERE url = ?
                    """, ('Malicious', current_time, current_time, url))
                    flash('The URL has been reported again and updated in the system.', 'success')
                else:
                    # If not reported before, insert a new record
                    cursor.execute("""
                        INSERT INTO phishing_reports (url, status, checked_at, malicious_votes, harmless_votes, last_analysis_date) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (url, 'Malicious', current_time, 1, 0, current_time))
                    flash('New phishing report submitted successfully.', 'success')

                conn.commit()

            except pyodbc.Error as db_err:
                flash(f"Database error: {db_err}", 'danger')

        # Instead of redirecting, render the report template again
        return render_template('report.html', form=form)  # Return the form with messages

    return render_template('report.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    response = make_response(redirect(url_for('login')))
    response.set_cookie('auth_token', '', expires=0)  # Clear the cookie on logout
    return response

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)
