from werkzeug.security import generate_password_hash, check_password_hash
from database.models import User
from database.connection import SessionLocal

def register_user(username, email, password, role='Analyst'):
    session = SessionLocal()
    try:
        # Check if user exists
        existing_user = session.query(User).filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            return False, "User with that username or email already exists."
        
        # Hash password and save
        hashed = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed, role=role)
        session.add(new_user)
        session.commit()
        return True, "User registered successfully."
    except Exception as e:
        session.rollback()
        return False, str(e)
    finally:
        session.close()

def authenticate_user(username, password):
    session = SessionLocal()
    try:
        user = session.query(User).filter(User.username == username).first()
        if user and check_password_hash(user.password_hash, password):
            # We return dict because SQLAlchemy object gets detached
            return True, {"id": user.id, "username": user.username, "role": user.role}
        return False, "Invalid username or password."
    finally:
        session.close()
