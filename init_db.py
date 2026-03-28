from app import app, db

def initialize():
    print("Connecting to database...")
    with app.app_context():
        print("Dropping old tables to clear legacy constraints...")
        db.drop_all()

        print("Creating updated tables...")
        db.create_all()

        print("Success! Your updated schema is ready.")

if __name__ == "__main__":
    initialize()
