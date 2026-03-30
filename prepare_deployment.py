import os
import tarfile
import shutil

DEPLOY_DIR = "deployment"

def setup_deployment_dir():
    # Create the deployment directory if it does not exist
    if not os.path.exists(DEPLOY_DIR):
        os.makedirs(DEPLOY_DIR)
        print(f"Created directory: {DEPLOY_DIR}")
    
    # List of files required for the production deployment
    items_to_copy = [
        "app.py", 
        "config.yaml", 
        "requirements.txt", 
        "init_db.py",
        ".env"
    ]
    
    # Copy files into the deployment directory
    for item in items_to_copy:
        if os.path.exists(item):
            shutil.copy2(item, os.path.join(DEPLOY_DIR, item))
            print(f"Copied {item} to {DEPLOY_DIR}/")
        else:
            print(f"Warning: {item} not found in the current directory, skipping.")
            
    # Copy the templates directory
    if os.path.exists("templates"):
        target_templates = os.path.join(DEPLOY_DIR, "templates")
        if os.path.exists(target_templates):
            shutil.rmtree(target_templates)
        shutil.copytree("templates", target_templates)
        print(f"Copied templates/ to {DEPLOY_DIR}/")

def create_dockerfile():
    dockerfile_content = """FROM python:3.10-slim

WORKDIR /app

# Install system dependencies required for psycopg2 and other packages
RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the Flask port
EXPOSE 5000

# Run with Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
"""
    with open(os.path.join(DEPLOY_DIR, "Dockerfile"), "w") as f:
        f.write(dockerfile_content)
    print("Created Dockerfile in deployment directory.")

def create_docker_compose():
    # Simplified to only include the web service
    compose_content = """version: '3.8'

services:
  web:
    build: .
    ports:
      - "5000:5000"
    env_file:
      - .env
    restart: unless-stopped
"""
    with open(os.path.join(DEPLOY_DIR, "docker-compose.yml"), "w") as f:
        f.write(compose_content)
    print("Created docker-compose.yml in deployment directory.")

def create_tar_archive(output_filename="deployment.tar.gz"):
    with tarfile.open(output_filename, "w:gz") as tar:
        # Pack the entire deployment directory into the archive
        tar.add(DEPLOY_DIR, arcname=DEPLOY_DIR)
    print(f"\\nSuccess: Packaging complete. Your deployable archive is {output_filename}")

if __name__ == "__main__":
    print("Starting deployment preparation...")
    setup_deployment_dir()
    create_dockerfile()
    create_docker_compose()
    create_tar_archive()