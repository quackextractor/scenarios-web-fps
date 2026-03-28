# INDUSTRIALIST QA Portal

## Application Architecture
This project is a centralized web portal designed for unmoderated testing and quality assurance of the INDUSTRIALIST project.

* **Frontend**: Rendered server-side using Jinja2 templates. Uses Bootstrap 5 for responsive design and UI components.
The form can dynamically generate scenarios based on the backend configuration and export reports locally to PDF using JavaScript.
* **Backend**: Powered by Python and the Flask framework. Handles incoming QA submissions, input validation, CSRF protection, and securely stores the test results.
It also exposes a webhook endpoint for automated deployment updates.
* **Database**: Transitioned to PostgreSQL for handling concurrency and multi-user scaling via Flask-SQLAlchemy. Local fallback utilizes SQLite.

## Technologies Used
* **Python**: 3.x
* **Flask**: 3.0.0 (Web framework)
* **Flask-SQLAlchemy**: 3.1.1 (ORM for database)
* **Flask-WTF**: 1.2.1 (Form handling and CSRF protection)
* **Flask-Compress**: 1.14 (GZIP compression for performance)
* **Flask-Mail**: 0.9.1 (Email delivery for OTP)
* **Flask-Limiter**: 3.3.1 (Rate limiting for authentication)
* **PyYAML**: 6.0.1 (Parsing test scenarios configuration)
* **python-dotenv**: 1.0.0 (Environment variable management)
* **Bleach**: 6.1.0 (HTML sanitization)
* **Gunicorn**: 20.1.0 (Production WSGI Server)
* **Bootstrap**: 5.3.0 (Frontend CSS framework)
* **html2pdf.js**: 0.10.1 (Frontend PDF generation)

## Production Deployment
Deploy the application using Gunicorn rather than the built-in Flask development server:
```bash
gunicorn -w 4 -b 127.0.0.1:5000 app:app