### Phase 1: Immediate Security and Infrastructure

* **Patch Stored XSS Vulnerability:** Add `bleach==6.1.0` to `requirements.txt`. In `app.py`, use Bleach to sanitize `issue_log` and `observations` before database insertion. In `templates/admin.html`, remove the `|safe` filter from `data.issue_log`  and `data.observations`.
* **Enforce Strict Secrets:** In `app.py`, replace `os.environ.get('SECRET_KEY', 'fallback_secret_key')`  with `os.environ['SECRET_KEY']`. Apply the exact same change for `os.environ.get('ADMIN_PASSWORD', 'fallback_admin_password')` in the login route.
* **Generate Dependency Lockfile:** Execute `pip freeze > requirements.txt` in the terminal to capture all exact versions of dependencies.
* **Implement Log Rotation:** In `app.py`, replace `logging.basicConfig`  with `logging.handlers.RotatingFileHandler('app.log', maxBytes=5000000, backupCount=5)`.
* **Add Configurable Test App Link:** Add `TEST_APP_URL` to `.env.example`. Pass this variable to `index.html` via the `render_template` function in `app.py`. Add an anchor tag pointing to this variable in `templates/index.html` just below the lead paragraph.

### Phase 2: Authentication and Access Control

* **School Email Authentication:** Add `SCHOOL_EMAIL_SUFFIX` to `.env.example`. Create a new `/login` route in `app.py`. Validate user input against `os.environ['SCHOOL_EMAIL_SUFFIX']`.
* **Email OTP Verification:** Integrate `Flask-Mail` into `requirements.txt`. Generate a 6 digit integer OTP on successful email validation, store it in the server session, and send it. Create a `/verify-otp` route to check user input against the session value and set `session['user_email']`.
* **Rate Limiting:** Add `Flask-Limiter` to requirements. Initialize it in `app.py` and apply `@limiter.limit("5 per minute")` specifically to the `/login` and `/verify-otp` routes.
* **Config-Based Admin Roles:** Add an `admin_emails` list to `config.yaml`. In `app.py`, update the `login_required` decorator  to verify if `session.get('user_email')` exists within `config_data.get('admin_emails', [])`.

### Phase 3: Administrative Capabilities

* **Admin Panel Whitelisting:** Add a `WhitelistedEmail` model in `app.py`. Update the `/login` route to explicitly allow access if the provided email exists in this database table, bypassing the school suffix check. Add a form in `templates/admin.html`  to submit new emails to a new `/admin/whitelist` POST route.
* **Admin Panel Blacklisting:** Add a `BlacklistedUser` model in `app.py`. Create a `/admin/blacklist` POST route. Prevent admins from locking out other admins by returning a 403 error if the target email is in `config_data['admin_emails']`. Add a management UI in `templates/admin.html`.
* **Database Management:** Create a `/admin/wipe_db` endpoint. Use the `shutil` module to copy `qa_database.db`  to a timestamped backup file before executing `db.drop_all()`.
* **Endpoint Relocation:** Move the `/stats` route definition  below the `login_required` decorator, and apply `@login_required` to secure it from public access.
* **Admin Dashboard Pagination:** Update the query in the `/admin` route  from `.all()` to `.paginate(page=request.args.get('page', 1, type=int), per_page=20)`. Update the loop in `templates/admin.html`  to iterate over `submissions.items` and add Bootstrap pagination controls.

### Phase 4: User Features and Scaling

* **Database Migration:** Add `psycopg2-binary` to `requirements.txt`. Update the `DATABASE_URI` format in `.env.example`  to a PostgreSQL connection string.
* **Editable Scenarios:** Add an `email` column to `TestSubmission`. Create a GET/POST `/edit/<int:submission_id>` route. The GET request must populate `index.html`  with existing data. The POST request must update the existing record instead of creating a new one, provided `session['user_email']` matches the record owner.
* **Enhanced Health Checks:** Add `psutil` to `requirements.txt`. Update the `/health` route  to execute `db.session.execute(text('SELECT 1'))`, `shutil.disk_usage('/')`, and `psutil.virtual_memory()`.
* **Production WSGI Server:** Add `gunicorn` to dependencies. Update `README.md` to run the application using Gunicorn  instead of the Flask development server.

### Phase 5: Code Hardening and Edge Cases

* **Data Validation Limits:** In the index POST route, immediately after retrieving `tester_name`, add `if len(tester_name) > 100: abort(400)` to prevent database errors.
* **Security Headers:** In the `add_security_and_cache_headers` function, append `response.headers['Content-Security-Policy']` and `response.headers['Strict-Transport-Security']`.
* **Session Teardown:** In the `admin_logout` function, replace `session.pop('admin_logged_in', None)` with `session.clear()` to destroy all temporary user data.
* **JavaScript Dependency Fallback:** In `templates/index.html`, remove the `d-none` class  and the `disabled` attributes. Add a vanilla JavaScript event listener on `DOMContentLoaded` to dynamically apply these properties so the form remains functional if scripts fail to load.
* **JSON Export Memory Management:** In the `/admin/export/json` route, replace `TestSubmission.query.all()` with `TestSubmission.query.yield_per(100)` and use `stream_with_context` to stream the JSON chunks to the client.