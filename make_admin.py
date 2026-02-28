import sys
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User

def make_admin(username: str):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            print(f"Error: User '{username}' not found.")
            return

        if user.is_admin:
            print(f"User '{username}' is already an admin.")
            return

        user.is_admin = True
        db.commit()
        print(f"Success! User '{username}' is now an admin.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)
        
    username = sys.argv[1]
    make_admin(username)
