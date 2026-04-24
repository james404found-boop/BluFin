from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Data(db.Model):
    __tablename__ = "data"

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    URL = db.Column(db.String(255), nullable=False)


class Users(db.Model):
    __tablename__ = "users"
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    AADHAR_NUMBER = db.Column(db.String(12), primary_key=True)  # Aadhaar is 12-digit, better as string
    EMAIL = db.Column(db.String(120), unique=True, nullable=False)
    PHONE_NUMBER = db.Column(db.String(15), nullable=False)  # keep as string (handles +91 etc.)
    PASSWORD = db.Column(db.String(255), nullable=False)

class Donor(db.Model):
    __tablename__ = "donors"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    name = db.Column(db.String(100), nullable=False)

    phone = db.Column(db.String(15), nullable=False, unique=True, index=True)

    address = db.Column(db.String(200), nullable=False)

    blood = db.Column(db.String(5), nullable=False)

    age = db.Column(db.Integer)

    gender = db.Column(db.String(10))

class Blacklist(db.Model):
    __tablename__ = "blacklist"

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), unique=True, nullable=False)
    domain = db.Column(db.String(255))
    reason = db.Column(db.String(255))
    score = db.Column(db.Integer)
    reported_by = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=db.func.now())


class Report(db.Model):
    __tablename__ = "reports"
    url = db.Column(db.String(500000))
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    description = db.Column(db.Text)
    
    image_path = db.Column(db.String(255))
    verdict = db.Column(db.String(50))
    score = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=db.func.now())

    