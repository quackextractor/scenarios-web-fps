### Phase 1: Immediate Security and Infrastructure
* **Patch Stored XSS Vulnerability:** Remove the `|safe` filter in the admin template and implement Bleach for HTML sanitization.
* **Enforce Strict Secrets:** Remove fallback values for `SECRET_KEY` and `ADMIN_PASSWORD` to ensure the application fails fast if the environment is misconfigured.
* **Generate Dependency Lockfile:** Freeze your Python packages to ensure consistent builds across environments.
* **Implement Log Rotation:** Prevent the `app.log` file from consuming all server disk space over time.
* Add a configurable link to the app, that is being tested (very important for testers): https://web-fps-sigma.vercel.app/

### Phase 2: Authentication and Access Control
* **School Email Authentication:** Implement a login flow utilizing a hidden, whitelisted school email suffix.
* **Email OTP Verification:** Send a 6-digit codep to the user's email for secure, passwordless authentication.
* **Rate Limiting:** Apply request limits to the login and OTP generation endpoints to prevent brute-force attacks and email spam.
* **Config-Based Admin Roles:** Allow specific email addresses to be designated as administrators directly within the application configuration file.

### Phase 3: Administrative Capabilities
* **Admin Panel Whitelisting:** Create a UI for administrators to manually add specific, non-school emails to the allowed list.
* **Admin Panel Blacklisting:** Allow admins to block specific users. Ensure the backend logic explicitly prevents admin accounts from being blacklisted.
* **Database Management:** Build a feature allowing admins to wipe the database. This must strictly enforce an automated, timestamped, non-overwriting backup prior to deletion.
* **Endpoint Relocation:** Move the public `/stats` route to reside securely behind the admin login.
* **Admin Dashboard Pagination:** Implement pagination for the submissions list to prevent memory overload as test data scales.

### Phase 4: User Features and Scaling
* **Database Migration:** Transition from SQLite to a robust relational database like PostgreSQL to handle concurrency and multi-user scaling.
* **Editable Scenarios:** Update the data model and UI to allow authenticated users to edit their own submitted scenarios.
* **Enhanced Health Checks:** Upgrade the `/health` endpoint to verify database connectivity, disk space, and memory usage rather than just returning a static status.
* **Production WSGI Server:** Deploy the application using Gunicorn or uWSGI instead of the built-in Flask development server.

### Phase 5: Code Hardening and Edge Cases

* **Data Validation Limits:** Your database model restricts the `tester_name` field to a maximum of 100 characters. The backend validation in your index route checks if the field is empty, but it does not check the length of the string. Submitting a name longer than 100 characters could cause an exception during the database commit.
* **Security Headers:** Your application explicitly sets the `X-Content-Type-Options`, `X-Frame-Options`, and `X-XSS-Protection` headers. You should expand this configuration to include a Content Security Policy (CSP) and an HTTP Strict Transport Security (HSTS) header.
* **Session Teardown:** Your `admin_logout` function selectively removes the `admin_logged_in` key from the active session. To prevent session fixation attacks and ensure all temporary user data is destroyed, you should completely clear the session object upon logout.
* **JavaScript Dependency Fallback:** Your frontend template disables the radio buttons and issue text areas by default. The application relies entirely on an event listener to enable these inputs when a user selects a scenario set. If a user has JavaScript disabled, or if the script fails to load, the form will remain disabled and unusable.
* **JSON Export Memory Management:** Your `/admin/export/json` endpoint retrieves all submissions using a single database query. Just as you identified the need for pagination on the admin dashboard to prevent memory overload, you should implement database chunking or a streaming response for this JSON export to handle future database growth safely.