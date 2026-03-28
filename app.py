import os
import json
import hmac
import hashlib
import subprocess
import logging
import logging.handlers
import random
import shutil
from datetime import datetime, timedelta, timezone
from functools import wraps
import yaml
import bleach
import psutil
from flask import Flask, render_template, request, make_response, jsonify, session, redirect, url_for, abort, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_compress import Compress
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

log_handler = logging.handlers.RotatingFileHandler('app.log', maxBytes=5000000, backupCount=5)
logging.basicConfig(handlers=[log_handler], level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'localhost')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 25))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'False') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@school.edu')

mail = Mail(app)

app.config['RATELIMIT_STORAGE_URI'] = os.environ.get('REDIS_URL', 'memory://')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day"],
    storage_options={"ssl_cert_reqs": None} if "upstash.io" in os.environ.get('REDIS_URL', '') else {}
)

Compress(app)
csrf = CSRFProtect(app)

db_uri = os.environ.get('DATABASE_URI', 'sqlite:///qa_database.db')
if db_uri.startswith('sqlite:///'):
    db_path = os.path.join(BASE_DIR, db_uri.replace('sqlite:///', ''))
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class TestSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    scenario_id = db.Column(db.String(50), nullable=False)
    test_date = db.Column(db.String(20), nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    submission_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    test_data = db.Column(db.Text, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('email', 'scenario_id', name='unique_email_scenario_id'),
    )

class WhitelistedEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

class BlacklistedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

with app.app_context():
    db.create_all()

config_path = os.path.join(BASE_DIR, 'config.yaml')
with open(config_path, 'r') as config_file:
    config_data = yaml.safe_load(config_file)
    SCENARIOS = config_data.get('scenarios', [])

def get_admin_emails():
    admins = os.environ.get('ADMIN_EMAILS', '')
    return [email.strip() for email in admins.split(',') if email.strip()]

def user_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_email'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_email = session.get('user_email')
        admin_emails = get_admin_emails()

        if not session.get('admin_logged_in') and (not user_email or user_email not in admin_emails):
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def add_security_and_cache_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self' https: 'unsafe-inline' 'unsafe-eval';"
    response.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains"

    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_errors(e):
    code = getattr(e, 'code', 500)
    description = getattr(e, 'description', "An unexpected error occurred.")
    return render_template('error.html', code=code, description=description), code

@app.route('/health', methods=['GET'])
def health_check():
    try:
        db.session.execute(text('SELECT 1'))
        db_status = "ok"
    except Exception:
        db_status = "error"

    disk = shutil.disk_usage('/')
    mem = psutil.virtual_memory()

    return jsonify({
        "status": "healthy" if db_status == "ok" else "unhealthy",
        "database": db_status,
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "memory_percent": mem.percent,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@app.route('/update_server', methods=['POST'])
@csrf.exempt
def webhook():
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        logging.warning("Webhook missing signature")
        abort(400, description="Missing signature")

    webhook_secret = os.environ.get('WEBHOOK_SECRET', '')
    secret = bytes(webhook_secret, 'utf-8')
    mac = hmac.new(secret, msg=request.data, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + mac.hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        logging.warning("Webhook invalid signature")
        abort(403, description="Invalid signature")

    repo_dir = os.environ.get('REPO_DIR')
    if repo_dir:
        subprocess.call(['git', 'pull'], cwd=repo_dir)
        subprocess.call(['/home/lustsoul/.virtualenvs/myvenv/bin/pip', 'install', '-r', 'requirements.txt'], cwd=repo_dir)

    wsgi_file = os.environ.get('WSGI_FILE')
    if wsgi_file:
        os.utime(wsgi_file, None)

    logging.info("Server updated via webhook successfully.")
    return "Updated successfully", 200

@app.route('/thanks')
@user_login_required
def thanks():
    return render_template('thanks.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        suffix = os.environ['SCHOOL_EMAIL_SUFFIX']
        whitelisted = WhitelistedEmail.query.filter_by(email=email).first()
        blacklisted = BlacklistedUser.query.filter_by(email=email).first()

        if blacklisted:
            return render_template('login.html', error="Your account has been blocked.")

        if email.endswith(suffix) or whitelisted:
            otp = str(random.randint(100000, 999999))
            session['pending_email'] = email
            session['otp'] = otp
            session['otp_expiry'] = (datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp()

            try:
                msg = Message("Your QA Portal OTP", recipients=[email])
                msg.body = f"Your login verification code is {otp}. It expires in 10 minutes."
                mail.send(msg)
            except Exception as e:
                logging.error(f"Failed to send OTP to {email}: {e}")

            return redirect(url_for('verify_otp'))
        else:
            return render_template('login.html', error="Unauthorized email domain.")

    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp', '').strip()
        otp_in_session = session.get('otp')
        expiry_timestamp = session.get('otp_expiry')

        if otp_in_session and expiry_timestamp:
            now = datetime.now(timezone.utc).timestamp()

            if now > expiry_timestamp:
                return render_template('verify_otp.html', error="Your code has expired. Please login again.")

            if user_otp == otp_in_session:
                session['user_email'] = session.get('pending_email')
                session.pop('otp', None)
                session.pop('otp_expiry', None)
                session.pop('pending_email', None)
                return redirect(url_for('index'))

        return render_template('verify_otp.html', error="Invalid or missing OTP.")
    return render_template('verify_otp.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@user_login_required
def index():
    user_email = session.get('user_email')
    test_app_url = os.environ.get('TEST_APP_URL')

    existing_submissions = TestSubmission.query.filter_by(email=user_email).all()
    submitted_scenarios = {sub.scenario_id: sub.id for sub in existing_submissions}

    if request.method == 'POST':
        test_date = request.form.get('test_date', '').strip()
        duration = request.form.get('duration', '').strip()
        selected_scenario = request.form.get('selected_scenario')

        if not test_date or not duration.isdigit() or not selected_scenario:
            logging.warning("Invalid input data submitted.")
            abort(400, description="Invalid data provided. Make sure to select a scenario.")

        if selected_scenario in submitted_scenarios:
            abort(400, description="You have already submitted a report for this scenario. Please edit it instead.")

        target_scenario = next((s for s in SCENARIOS if s['id'] == selected_scenario), None)
        if not target_scenario:
            abort(400, description="Invalid scenario selected.")

        steps_data = []
        for i in range(len(target_scenario['steps'])):
            step_val = request.form.get(f"{selected_scenario}_step_{i}")
            steps_data.append(step_val if step_val in ['pass', 'fail', 'hard'] else None)

        results = {
            'steps': steps_data,
            'issue_log': bleach.clean(request.form.get(f"{selected_scenario}_issue", "")),
            'observations': bleach.clean(request.form.get(f"{selected_scenario}_obs", ""))
        }

        new_submission = TestSubmission(
            email=user_email,
            scenario_id=selected_scenario,
            test_date=test_date,
            duration=int(duration),
            test_data=json.dumps(results)
        )

        try:
            db.session.add(new_submission)
            db.session.commit()
            logging.info(f"New submission saved securely from {user_email}.")
            return redirect(url_for('thanks'))
        except IntegrityError:
            db.session.rollback()
            abort(400, description="Database verification failed: You have already submitted a report for this specific scenario.")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Database error during submission: {e}")
            abort(500, description="An error occurred while saving your submission.")

    return render_template('index.html', scenarios=SCENARIOS, test_app_url=test_app_url, edit_sub=None, parsed_data={}, submitted_scenarios=submitted_scenarios, user_email=user_email)

@app.route('/edit/<int:submission_id>', methods=['GET', 'POST'])
@user_login_required
def edit_submission(submission_id):
    sub = TestSubmission.query.get_or_404(submission_id)
    user_email = session.get('user_email')

    if user_email != sub.email:
        abort(403, description="You are not authorized to edit this submission.")

    editing_scenario = sub.scenario_id

    if request.method == 'POST':
        test_date = request.form.get('test_date', '').strip()
        duration = request.form.get('duration', '').strip()

        if not test_date or not duration.isdigit():
            abort(400, description="Invalid data provided.")

        target_scenario = next((s for s in SCENARIOS if s['id'] == editing_scenario), None)
        if not target_scenario:
            abort(400, description="Invalid scenario configuration.")

        steps_data = []
        for i in range(len(target_scenario['steps'])):
            step_val = request.form.get(f"{editing_scenario}_step_{i}")
            steps_data.append(step_val if step_val in ['pass', 'fail', 'hard'] else None)

        results = {
            'steps': steps_data,
            'issue_log': bleach.clean(request.form.get(f"{editing_scenario}_issue", "")),
            'observations': bleach.clean(request.form.get(f"{editing_scenario}_obs", ""))
        }

        sub.test_date = test_date
        sub.duration = int(duration)
        sub.test_data = json.dumps(results)

        try:
            db.session.commit()
            logging.info(f"Submission {sub.id} successfully updated.")
            return redirect(url_for('thanks'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating submission {sub.id}: {e}")
            abort(500, description="Failed to update your submission.")

    try:
        parsed_data = json.loads(sub.test_data)
    except json.JSONDecodeError:
        parsed_data = {}

    test_app_url = os.environ.get('TEST_APP_URL')
    return render_template('index.html', scenarios=SCENARIOS, test_app_url=test_app_url, edit_sub=sub, parsed_data=parsed_data, submitted_scenarios={}, editing_scenario=editing_scenario, user_email=user_email)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        admin_pass = os.environ['ADMIN_PASSWORD']
        next_page = request.args.get('next')

        if hmac.compare_digest(password.encode('utf-8'), admin_pass.encode('utf-8')):
            session['admin_logged_in'] = True
            return redirect(next_page or url_for('admin_dashboard'))

        return render_template('admin_login.html', error="Invalid credentials.")

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    page = request.args.get('page', 1, type=int)
    submissions = TestSubmission.query.order_by(TestSubmission.submission_time.desc()).paginate(page=page, per_page=20)
    for sub in submissions.items:
        try:
            sub.parsed_data = json.loads(sub.test_data)
        except json.JSONDecodeError:
            sub.parsed_data = {}

    return render_template('admin.html', submissions=submissions)

@app.route('/stats', methods=['GET'])
@login_required
def stats():
    try:
        total = TestSubmission.query.count()
        return jsonify({"total_submissions": total}), 200
    except Exception:
        return jsonify({"error": "Database error"}), 500

@app.route('/admin/whitelist', methods=['POST'])
@login_required
def admin_whitelist():
    email = request.form.get('email', '').strip()
    if email:
        try:
            db.session.add(WhitelistedEmail(email=email))
            db.session.commit()
        except Exception:
            db.session.rollback()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/blacklist', methods=['POST'])
@login_required
def admin_blacklist():
    email = request.form.get('email', '').strip()
    if email in get_admin_emails():
        abort(403, description="Cannot blacklist an administrator account.")
    if email:
        try:
            db.session.add(BlacklistedUser(email=email))
            db.session.commit()
        except Exception:
            db.session.rollback()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/wipe_db', methods=['POST'])
@login_required
def admin_wipe_db():
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    backup_path = f"qa_database_{timestamp}.db"
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']

    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
        if os.path.exists(db_path):
            shutil.copy2(db_path, backup_path)

    db.drop_all()
    db.create_all()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/export/json', methods=['GET'])
@login_required
def export_json():
    def generate():
        yield '['
        first = True
        for sub in TestSubmission.query.yield_per(100):
            if not first:
                yield ','
            first = False
            try:
                parsed_test_data = json.loads(sub.test_data)
            except json.JSONDecodeError:
                parsed_test_data = {}

            item = {
                "id": sub.id,
                "email": sub.email,
                "scenario_id": sub.scenario_id,
                "test_date": sub.test_date,
                "duration_minutes": sub.duration,
                "submission_time": sub.submission_time.isoformat(),
                "results": parsed_test_data
            }
            yield json.dumps(item)
        yield ']'

    response = make_response(app.response_class(stream_with_context(generate()), mimetype='application/json'))
    response.headers["Content-Disposition"] = "attachment; filename=industrialist_qa_export.json"
    response.headers["Content-Type"] = "application/json"
    return response

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)
