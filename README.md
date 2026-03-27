# INDUSTRIALIST QA Portal

## Application Architecture
This project is a centralized web portal designed for unmoderated testing and quality assurance of the INDUSTRIALIST project.

* **Frontend**: Rendered server-side using Jinja2 templates. Uses Bootstrap 5 for responsive design and UI components. The form can dynamically generate scenarios based on the backend configuration and export reports locally to PDF using JavaScript.
* **Backend**: Powered by Python and the Flask framework. Handles incoming QA submissions, input validation, CSRF protection, and securely stores the test results. It also exposes a webhook endpoint for automated deployment updates.
* **Database**: Uses SQLite via Flask-SQLAlchemy to locally store user sessions and testing submissions.

## Technologies Used
* **Python**: 3.x
* **Flask**: 3.0.0 (Web framework)
* **Flask-SQLAlchemy**: 3.1.1 (ORM for SQLite database)
* **Flask-WTF**: 1.2.1 (Form handling and CSRF protection)
* **Flask-Compress**: 1.14 (GZIP compression for performance)
* **PyYAML**: 6.0.1 (Parsing test scenarios configuration)
* **python-dotenv**: 1.0.0 (Environment variable management)
* **Bootstrap**: 5.3.0 (Frontend CSS framework)
* **html2pdf.js**: 0.10.1 (Frontend PDF generation)