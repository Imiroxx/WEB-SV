from app import application, db

with application.app_context():
    # Create all tables
    db.create_all()
    print("Database tables created successfully!") 