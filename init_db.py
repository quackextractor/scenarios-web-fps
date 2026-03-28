from app import app, db

def initialize():
    print("Connecting to Neon...")
    with app.app_context():
        # This looks at your User/OTP models and creates them in Postgres
        db.create_all()
        print("Success! Your tables have been created on Neon.")

if __name__ == "__main__":
    initialize()