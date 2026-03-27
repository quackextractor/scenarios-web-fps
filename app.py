from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import hmac
import hashlib
import subprocess
import os
import yaml
from dotenv import load_dotenv

# Calculate the absolute path of the directory containing app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load environment variables using the absolute path to .env
load_dotenv(os.path.join(BASE_DIR, '.env'))

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')

# Construct absolute path for the SQLite database to avoid directory confusion
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

# Create the absolute path to your config file
config_path = os.path.join(BASE_DIR, 'config.yaml')

# Load scenarios from config.yaml
with open(config_path, 'r') as config_file:
    config_data = yaml.safe_load(config_file)
    SCENARIOS = config_data.get('scenarios', [])

@app.route('/update_server', methods=['POST'])
def webhook():
    if request.method == 'POST':
        signature = request.headers.get('X-Hub-Signature-256')
        if not signature:
            return "Missing signature", 400

        webhook_secret = os.environ.get('WEBHOOK_SECRET', '')
        secret = bytes(webhook_secret, 'utf-8')
        mac = hmac.new(secret, msg=request.data, digestmod=hashlib.sha256)
        expected_signature = "sha256=" + mac.hexdigest()
        
        if not hmac.compare_digest(expected_signature, signature):
            return "Invalid signature", 403

        repo_dir = os.environ.get('REPO_DIR')
        if repo_dir:
            subprocess.call(['git', 'pull'], cwd=repo_dir)
        
        wsgi_file = os.environ.get('WSGI_FILE')
        if wsgi_file:
            os.utime(wsgi_file, None)
        
        return "Updated successfully", 200

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        tester_name = request.form.get('tester_name')
        test_date = request.form.get('test_date')
        duration = request.form.get('duration')
        
        results = {}
        for scenario in SCENARIOS:
            s_id = scenario['id']
            results[s_id] = {
                'steps': [request.form.get(f"{s_id}_step_{i}") for i in range(len(scenario['steps']))],
                'issue_log': request.form.get(f"{s_id}_issue"),
                'observations': request.form.get(f"{s_id}_obs")
            }
        
        new_submission = TestSubmission(
            tester_name=tester_name,
            test_date=test_date,
            duration=int(duration),
            test_data=json.dumps(results)
        )
        db.session.add(new_submission)
        db.session.commit()
        
        return "Submission saved successfully. Thank you for testing."

    return render_template('index.html', scenarios=SCENARIOS)

if __name__ == '__main__':
    # Parse debug flag from environment
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)