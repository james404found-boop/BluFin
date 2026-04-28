from flask import Flask, jsonify, render_template, redirect, url_for, request, session, send_from_directory
from models import *
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename
import datetime

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQL_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

from ai import classify

# ------------------ UTIL ------------------

from urllib.parse import urlparse
import requests
import socket
import ssl
import whois
from bs4 import BeautifulSoup
import urlextract

def extract_url(text):
    extractor = urlextract.URLExtract()
    return extractor.find_urls(text)

def is_blacklisted(url):
    if not url:
        return None
    domain = urlparse(url).netloc
    return Blacklist.query.filter(
        (Blacklist.url == url) | (Blacklist.domain == domain)
    ).first()

def ocr_image(file_path):
    try:
        url = "https://api.ocr.space/parse/image"
        with open(file_path, 'rb') as f:
            response = requests.post(
                url,
                files={"file": f},
                data={"apikey": os.getenv('OCR_API_KEY')}
            )
        result = response.json()
        return result['ParsedResults'][0]['ParsedText']
    except Exception as e:
        return ""

# ------------------ ROUTES ------------------

@app.route("/test")
def test():
    return "WORKING"

@app.route("/")
def root():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template("home.html")

@app.route("/home")
def home():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template("home.html")

# ------------------ PHISHING ------------------

@app.route("/check", methods=["GET", "POST"])
def check():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        try:
            email = request.form.get("Email")
            desc = request.form.get("Description")
            screenshot = request.files.get("Image")
            url_input = request.form.get("Url")

            text = ""

            # OCR
            if screenshot:
                path = os.path.join('uploads', secure_filename(screenshot.filename))
                screenshot.save(path)
                text = ocr_image(path)

            urls = extract_url(text) if text else []

            if url_input:
                urls.append(url_input)

            # AI SAFE WRAPPER
            try:
                ai_result = classify(email, desc, screenshot_info=text, urls=urls)
            except Exception as e:
                ai_result = "ERROR in AI"

            # URL ANALYSIS SAFE
            url_analysis = None
            if urls:
                url_analysis = {
                    "score": 50,
                    "reasons": ["Basic analysis only (safe mode)"]
                }

            blacklist_hit = None
            if urls:
                blacklist_hit = is_blacklisted(urls[0])

            return jsonify({
                "url_analysis": url_analysis,
                "ai_result": ai_result,
                "blacklisted": True if blacklist_hit else False
            })

        except Exception as e:
            return jsonify({"error": str(e)})

    return render_template("check.html")

# ------------------ REPORT ------------------

@app.route("/report", methods=["GET", "POST"])
def report():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        try:
            email = request.form.get("Email")
            description = request.form.get("description")
            url = request.form.get("Url")

            score = 50
            verdict = "PHISHING" if score > 60 else "SAFE"

            new_report = Report(
                email=email,
                description=description,
                url=url,
                verdict=verdict,
                score=score
            )

            db.session.add(new_report)
            db.session.commit()

            return jsonify({
                "message": "Report submitted",
                "verdict": verdict,
                "score": score
            })

        except Exception as e:
            return jsonify({"error": str(e)})

    return render_template("report.html")

# ------------------ AUTH ------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user' in session:
        return redirect(url_for('root'))

    if request.method == "POST":
        data = request.get_json()
        user = Users.query.filter_by(EMAIL=data.get("email")).first()

        if not user:
            return jsonify(msg="email not registered"), 400

        if user.PASSWORD != data.get("password"):
            return jsonify(msg="wrong password"), 401

        session["user"] = user.EMAIL
        return jsonify(msg="login success")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def registration():
    if request.method == "POST":
        data = request.get_json()

        user = Users(
            AADHAR_NUMBER=data.get("aadhaar_number"),
            EMAIL=data.get("email"),
            PHONE_NUMBER=data.get("phone_number"),
            PASSWORD=data.get("password")
        )

        db.session.add(user)
        db.session.commit()

        return jsonify(msg="registered")

    return render_template("register.html")

@app.post('/clearsession')
def clear_session():
    session.clear()
    return jsonify({"message": "logged out"})

# ------------------ BLOOD DONOR ------------------

@app.route('/find-donor')
def find_donor():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('bloodfinder.html')

@app.route('/register-donor', methods=["POST"])
def register_donor():
    try:
        data = request.get_json()

        donor = Donor(
            name=data.get("name"),
            phone=data.get("phone"),
            address=data.get("address"),
            blood=data.get("blood"),
            age=data.get("age"),
            gender=data.get("gender")
        )

        db.session.add(donor)
        db.session.commit()

        return jsonify({"message": "Donor registered"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/find-donors', methods=["POST"])
def find_donors():
    data = request.get_json()
    blood = data.get("blood")
    location = data.get("location")

    query = Donor.query

    if blood:
        query = query.filter_by(blood=blood)

    if location:
        query = query.filter(Donor.address.ilike(f"%{location}%"))

    donors = query.all()

    return jsonify({
        "donors": [
            {
                "name": d.name,
                "blood": d.blood,
                "location": d.address,
                "phone": d.phone
            } for d in donors
        ]
    })

# ------------------ RUN ------------------

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))  # 🔥 FIX FOR RAILWAY
    app.run(host='0.0.0.0', port=port)
