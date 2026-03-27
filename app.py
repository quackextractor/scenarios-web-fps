import os
import json
import hmac
import hashlib
import subprocess
import logging
from datetime import datetime
from functools import wraps
import yaml
from flask import Flask, render_template, request, make_response, jsonify, session, redirect, url_for, abort
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
    id = db.Model.id = db.Column(db.Integer, primary_key=True)
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
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_errors(e):
    """Unified error handler for comprehensible user feedback (Checklist 3.3, 3.4)."""
    code = getattr(e, 'code', 500)
    description = getattr(e, 'description', "An unexpected error occurred.")
    return render_template('error.html', code=code, description=description), code

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()}), 200

@app.route('/stats', methods=['GET'])
def stats():
    try:
        total = TestSubmission.query.count()
        return jsonify({"total_submissions": total}), 200
    except Exception:
        return jsonify({"error": "Database error"}), 500

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
    
    wsgi_file = os.environ.get('WSGI_FILE')
    if wsgi_file:
        os.utime(wsgi_file, None)
    
    logging.info("Server updated via webhook successfully.")
    return "Updated successfully", 200

@app.route('/thanks')
def thanks():
    """Success page to prevent form resubmission on refresh."""
    return render_template('thanks.html')

@app.route('/', methods=['GET', 'POST'])
def index():
    scenario_sets = {}
    for scenario in SCENARIOS:
        set_prefix = scenario['id'].rsplit('-', 1)[0]
        if set_prefix not in scenario_sets:
            scenario_sets[set_prefix] = []
        scenario_sets[set_prefix].append(scenario)
        
    if request.method == 'POST':
        tester_name = request.form.get('tester_name', '').strip()
        test_date = request.form.get('test_date', '').strip()
        duration = request.form.get('duration', '').strip()
        selected_sets = request.form.getlist('selected_sets')
        
        if not tester_name or not test_date or not duration.isdigit() or not selected_sets:
            logging.warning("Invalid input data submitted.")
            abort(400, description="Invalid data provided. Make sure to select at least one scenario set.")

        results = {}
        for scenario in SCENARIOS:
            set_prefix = scenario['id'].rsplit('-', 1)[0]
            if set_prefix not in selected_sets:
                continue
              
            s_id = scenario['id']
            steps_data = []
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
            return redirect(url_for('thanks'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Database error during submission: {e}")
            abort(500, description="An error occurred while saving your submission.")

    return render_template('index.html', scenario_sets=scenario_sets)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        admin_pass = os.environ.get('ADMIN_PASSWORD', 'fallback_admin_password')
        next_page = request.args.get('next')
        
        if hmac.compare_digest(password.encode('utf-8'), admin_pass.encode('utf-8')):
            session['admin_logged_in'] = True
            return redirect(next_page or url_for('admin_dashboard'))
            
        return render_template('admin_login.html', error="Invalid credentials.")
        
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    submissions = TestSubmission.query.order_by(TestSubmission.submission_time.desc()).all()
    for sub in submissions:
        try:
            sub.parsed_data = json.loads(sub.test_data)
        except json.JSONDecodeError:
            sub.parsed_data = {}
            
    return render_template('admin.html', submissions=submissions)

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)