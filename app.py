import os
import json
import hmac
import hashlib
import subprocess
import logging
from datetime import datetime
from functools import wraps
import yaml
from flask import Flask, render_template, request, make_response, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_compress import Compress

# Configure application logging (Checklist 9.1, 9.2)
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')

# Security configuration for cookies (Checklist 7.6)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Enable GZIP Compression (Checklist 3.7, 4.8)
Compress(app)

# Enable CSRF Protection (Checklist 7.3)
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
    tester_name = db.Column(db.String(100), nullable=False)
    test_date = db.Column(db.String(20), nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    submission_time = db.Column(db.DateTime, default=datetime.utcnow)
    test_data = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()

config_path = os.path.join(BASE_DIR, 'config.yaml')

with open(config_path, 'r') as config_file:
    config_data = yaml.safe_load(config_file)
    SCENARIOS = config_data.get('scenarios', [])

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def add_security_and_cache_headers(response):
    # Add standard security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Cache control for general performance (Checklist 5.1, 5.2)
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

@app.route('/health', methods=['GET'])
def health_check():
    """API Endpoint: GET /health for uptime monitoring (Checklist 9.6)"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()}), 200

@app.route('/stats', methods=['GET'])
def stats():
    """API Endpoint: GET /stats for monitoring (Checklist 9.4)"""
    try:
        total = TestSubmission.query.count()
        return jsonify({"total_submissions": total}), 200
    except Exception:
        return jsonify({"error": "Database error"}), 500

@app.route('/update_server', methods=['POST'])
@csrf.exempt # Webhooks rely on HMAC, not CSRF tokens
def webhook():
    """
    API Endpoint: POST /update_server
    Description: Receives Git webhook payloads to trigger automatic server pulls and restarts.
    Security: Validates payload using HMAC SHA256 against WEBHOOK_SECRET.
    Returns: 
        - 200 OK: Updated successfully.
        - 400 Bad Request: Missing signature.
        - 403 Forbidden: Invalid signature.
    """
    if request.method == 'POST':
        signature = request.headers.get('X-Hub-Signature-256')
        if not signature:
            logging.warning("Webhook missing signature")
            return "Missing signature", 400

        webhook_secret = os.environ.get('WEBHOOK_SECRET', '')
        secret = bytes(webhook_secret, 'utf-8')
        mac = hmac.new(secret, msg=request.data, digestmod=hashlib.sha256)
        expected_signature = "sha256=" + mac.hexdigest()
        
        if not hmac.compare_digest(expected_signature, signature):
            logging.warning("Webhook invalid signature")
            return "Invalid signature", 403

        repo_dir = os.environ.get('REPO_DIR')
        if repo_dir:
            subprocess.call(['git', 'pull'], cwd=repo_dir)
        
        wsgi_file = os.environ.get('WSGI_FILE')
        if wsgi_file:
            os.utime(wsgi_file, None)
        
        logging.info("Server updated via webhook successfully.")
        return "Updated successfully", 200

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    API Endpoint: GET/POST /
    Description: 
        - GET: Renders the QA portal interface grouped by scenario sets.
        - POST: Processes QA form submissions, formats data, and securely saves it to the database.
    Validation: Enforces basic input checks for tester name, date, and duration.
    Returns: 
        - 200 OK: Renders HTML (GET) or returns success string (POST).
        - 400 Bad Request: Invalid or missing form data.
        - 500 Internal Server Error: Database failure.
    """
    
    # Group scenarios by their prefix (e.g., TS-A) for the frontend logic
    scenario_sets = {}
    for scenario in SCENARIOS:
        set_prefix = scenario['id'].rsplit('-', 1)[0]
        if set_prefix not in scenario_sets:
            scenario_sets[set_prefix] = []
        scenario_sets[set_prefix].append(scenario)
        
    if request.method == 'POST':
        # Sanitize and validate basic inputs (Checklist 7.1, 7.5)
        tester_name = request.form.get('tester_name', '').strip()
        test_date = request.form.get('test_date', '').strip()
        duration = request.form.get('duration', '').strip()
        selected_sets = request.form.getlist('selected_sets')
        
        if not tester_name or not test_date or not duration.isdigit() or not selected_sets:
            logging.warning("Invalid input data submitted.")
            return "Invalid data provided. Make sure to select at least one scenario set.", 400

        results = {}
        for scenario in SCENARIOS:
            set_prefix = scenario['id'].rsplit('-', 1)[0]
            if set_prefix not in selected_sets:
                continue
                
            s_id = scenario['id']
            steps_data = []
            
            # Validate step choices
            for i in range(len(scenario['steps'])):
                step_val = request.form.get(f"{s_id}_step_{i}")
                steps_data.append(step_val if step_val in ['pass', 'fail', 'hard'] else None)
            
            results[s_id] = {
                'steps': steps_data,
                'issue_log': request.form.get(f"{s_id}_issue", ""),
                'observations': request.form.get(f"{s_id}_obs", "")
            }
        
        new_submission = TestSubmission(
            tester_name=tester_name,
            test_date=test_date,
            duration=int(duration),
            test_data=json.dumps(results)
        )
        
        try:
            db.session.add(new_submission)
            db.session.commit()
            logging.info(f"New submission saved securely from {tester_name}.")
            return "Submission saved successfully. Thank you for testing.", 200
        except Exception as e:
            db.session.rollback()
            logging.error(f"Database error during submission: {e}")
            # Ensure no internal errors are leaked (Checklist 3.4)
            return "An error occurred while saving submission.", 500

    return render_template('index.html', scenario_sets=scenario_sets)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Secure endpoint for admin authentication."""
    if request.method == 'POST':
        password = request.form.get('password', '')
        admin_pass = os.environ.get('ADMIN_PASSWORD', 'fallback_admin_password')
        
        # Prevent timing attacks using compare_digest
        if hmac.compare_digest(password.encode('utf-8'), admin_pass.encode('utf-8')):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
            
        return render_template('admin_login.html', error="Invalid credentials.")
        
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Clears the admin session."""
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    """Protected endpoint to view submissions."""
    submissions = TestSubmission.query.order_by(TestSubmission.submission_time.desc()).all()
    
    # Parse JSON strings back into dictionaries for Jinja rendering
    for sub in submissions:
        try:
            sub.parsed_data = json.loads(sub.test_data)
        except json.JSONDecodeError:
            sub.parsed_data = {}
            
    return render_template('admin.html', submissions=submissions)

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)