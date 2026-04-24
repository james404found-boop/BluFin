from flask import Flask, jsonify, render_template, redirect, url_for, request, session, send_from_directory
from models import *
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename
import requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQL_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

from ai import classify





# ------------------ UTIL FUNCTIONS ------------------


from urllib.parse import urlparse

def is_blacklisted(url):
    if not url:
        return None

    domain = urlparse(url).netloc

    entry = Blacklist.query.filter(
        (Blacklist.url == url) | (Blacklist.domain == domain)
    ).first()

    return entry

import requests
import socket
import ssl
import whois
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

def analyze_url(url):
    score = 0
    reasons = []

    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        # ---------------- BASIC CHECKS ----------------

        if len(url) > 75:
            score += 10
            reasons.append("URL is too long")

        if "@" in url:
            score += 10
            reasons.append("Contains @ symbol (redirect trick)")

        if "-" in domain:
            score += 5
            reasons.append("Hyphen in domain")

        # IP address instead of domain
        try:
            socket.inet_aton(domain)
            score += 20
            reasons.append("Uses IP address instead of domain")
        except:
            pass

        # ---------------- DOMAIN AGE ----------------

        try:
            w = whois.whois(domain)
            if w.creation_date:
                age_days = (datetime.datetime.now() - w.creation_date).days
                if age_days < 180:
                    score += 15
                    reasons.append("Domain is very new")
        except:
            score += 5
            reasons.append("WHOIS data unavailable")

        # ---------------- SSL CHECK ----------------

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3)
                s.connect((domain, 443))
        except:
            score += 15
            reasons.append("Invalid or missing SSL")

        # ---------------- REQUEST PAGE ----------------

        response = requests.get(url, timeout=5)
        html = response.text

        # ---------------- HEADERS ----------------

        headers = response.headers
        if "X-Frame-Options" not in headers:
            score += 5
            reasons.append("Missing X-Frame-Options")

        if "Content-Security-Policy" not in headers:
            score += 5
            reasons.append("Missing CSP")

        # ---------------- HTML ANALYSIS ----------------

        soup = BeautifulSoup(html, "html.parser")

        # Forms
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            if action and urlparse(action).netloc != domain:
                score += 15
                reasons.append("Form submits to external domain")

        # External links ratio
        links = soup.find_all("a", href=True)
        external = 0

        for link in links:
            href = link["href"]
            if href.startswith("http") and domain not in href:
                external += 1

        if links and (external / len(links)) > 0.6:
            score += 10
            reasons.append("Too many external links")

        # JS suspicious
        scripts = soup.find_all("script")
        for s in scripts:
            if s.string and "eval(" in s.string:
                score += 10
                reasons.append("Uses eval() in JS")

        # ---------------- KEYWORDS ----------------

        suspicious_words = ["login", "verify", "bank", "secure", "update", "free", "bonus"]
        for word in suspicious_words:
            if word in url.lower():
                score += 5
                reasons.append(f"Suspicious keyword: {word}")

        # ---------------- REDIRECTS ----------------

        if len(response.history) > 2:
            score += 10
            reasons.append("Multiple redirects detected")

    except Exception as e:
        return {
            "score": 50,
            "reasons": [f"Analysis error: {str(e)}"]
        }

    return {
        "score": min(score, 100),
        "reasons": reasons
    }

def extract_url(text: str) -> list:
    import urlextract
    extractor = urlextract.URLExtract()
    return extractor.find_urls(text)


def ocr_image(file_path):
    url = "https://api.ocr.space/parse/image"

    with open(file_path, 'rb') as f:
        response = requests.post(
            url,
            files={"file": f},
            data={"apikey": os.getenv('OCR_API_KEY')}
        )

    result = response.json()
    return result['ParsedResults'][0]['ParsedText']


# ------------------ ROUTES ------------------




@app.route("/", methods=["GET", "POST"])
def root():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        return redirect(url_for('check'))

    return send_from_directory('templates', 'home.html')

@app.route("/home")
def home():
    if 'user' not in session:
        return redirect(url_for('login'))
    return send_from_directory('templates', 'home.html')


# ------------------ PHISHING ------------------

@app.route("/check", methods=["GET", "POST"])
def check():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        text = ''
        email = request.form.get("Email")
        user_context = request.form.get("description")
        screenshot = request.files.get("Image")
        url_input = request.form.get("Url")

        if screenshot:
            path = os.path.join('uploads', secure_filename(screenshot.filename))
            screenshot.save(path)
            text = ocr_image(path)

        urls = extract_url(text) if text else []

        # include manually entered URL
        if url_input:
            urls.append(url_input)

        ai_result = classify(email, user_context, screenshot_info=text, urls=urls)

        url_analysis = None
        if urls:
            url_analysis = analyze_url(urls[0])  # analyze first URL
        blacklist_hit = None
        if urls:
            blacklist_hit = is_blacklisted(urls[0])
        return jsonify({
    "url_analysis": url_analysis,
    "ai_result": ai_result,
    "blacklisted": True if blacklist_hit else False
})

    return render_template('check.html')



@app.route("/report", methods=["GET", "POST"])
def report():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":

        email = request.form.get("Email")
        description = request.form.get("description")
        url = request.form.get("Url")
        screenshot = request.files.get("Image")

        text = ""
        image_path = None

        if screenshot:
            image_path = os.path.join('uploads', secure_filename(screenshot.filename))
            screenshot.save(image_path)
            text = ocr_image(image_path)

        urls = []
        if url:
            urls.append(url)

        # 🔥 analyze
        url_result = analyze_url(url) if url else None
        ai_result = classify(email, description, screenshot_info=text, urls=urls)

        score = url_result["score"] if url_result else 0

        verdict = "PHISHING" if score > 60 or ai_result == "PHISHING" else "SAFE"

        # ✅ STORE REPORT
        new_report = Report(
            email=email,
            description=description,
            url=url,
            image_path=image_path,
            verdict=verdict,
            score=score
        )

        db.session.add(new_report)

        # 🔥 AUTO BLACKLIST
        if verdict == "PHISHING" and url:
            domain = urlparse(url).netloc

            exists = Blacklist.query.filter_by(url=url).first()

            if not exists:
                black = Blacklist(
                    url=url,
                    domain=domain,
                    reason="User reported + AI flagged",
                    score=score,
                    reported_by=email
                )
                db.session.add(black)

        db.session.commit()

        return jsonify({
            "message": "Report submitted",
            "verdict": verdict,
            "score": score
        })

    return send_from_directory("templates", "report.html")








# ------------------ URL STORAGE ------------------

@app.route("/submiturl", methods=["GET", "POST"])
def submiturl():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        data = request.get_json()
        url = data.get("url")

        db.session.add(Data(URL=url))
        db.session.commit()

    return render_template('submiturl.html')


@app.route("/phishurls")
def see_url():
    if 'user' not in session:
        return redirect(url_for('login'))

    urls = Data.query.all()
    return jsonify([{"id": u.ID, "url": u.URL} for u in urls])


@app.route("/see_url")
def see_url_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('see_url.html')


# ------------------ AUTH ------------------

@app.route("/register", methods=["GET", "POST"])
def registration():
    if 'user' in session:
        return redirect(url_for('root'))

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

        return jsonify(msg="go and login"), 200

    return send_from_directory('templates', 'register.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user' in session:
        return redirect(url_for('root'))

    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = Users.query.filter_by(EMAIL=email).first()

        if not user:
            return jsonify(msg="email not registered"), 400

        if user.PASSWORD != password:
            return jsonify(msg="wrong password"), 401

        session["user"] = user.EMAIL
        return jsonify(msg="login success"), 200

    return send_from_directory('templates', 'login.html')


@app.route('/clearsession')
def clear_session():
    session.clear()
    return redirect(url_for('login'))


# ------------------ BLOOD DONOR ------------------

@app.route('/blood-donor')
def donor():
    if 'user' not in session:
        return redirect(url_for('login'))
    return send_from_directory('templates', 'blood_donor.html')

@app.route('/register-donor')
def register_donor_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    return send_from_directory('templates', 'bloodreg.html')


@app.route('/register-donor', methods=["POST"])
def register_donor():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    name = data.get("name")
    phone = data.get("phone")
    address = data.get("address")
    blood = data.get("blood")
    age = data.get("age")
    gender = data.get("gender")

    # 🔴 Basic validation
    if not name or not phone or not address or not blood:
        return jsonify({"error": "Missing required fields"}), 400

    # 🔴 Check duplicate phone
    existing = Donor.query.filter_by(phone=phone).first()
    if existing:
        return jsonify({"error": "Donor with this phone already exists"}), 409

    try:
        donor = Donor(
            name=name,
            phone=phone,
            address=address,
            blood=blood,
            age=age,
            gender=gender
        )

        db.session.add(donor)
        db.session.commit()

        return jsonify({"message": "Donor registered successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Database error"}), 500

@app.route('/find-donor')
def find_donor():
    if 'user' not in session:
        return redirect(url_for('login'))
    return send_from_directory('templates', 'bloodfinder.html')



@app.route('/find-donors', methods=["POST"])
def find_donors():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    blood = data.get("blood")
    location = data.get("location").strip()

    query = Donor.query

    if blood:
        query = query.filter_by(blood=blood)

    if location:
        query = query.filter(Donor.address.ilike(f"%{location}%"))

    donors = query.all()

    result = []
    for d in donors:
        result.append({
            "name": d.name,
            "blood": d.blood,
            "location": d.address,
            "phone": d.phone,
            "email": "N/A",
            "lat": 17.385,
            "lng": 78.486
        })

    return jsonify({"donors": result})


# ------------------ REPORT ------------------




# ------------------ RUN ------------------

if __name__ == '__main__': 
    app.run(threaded=True, host='0.0.0.0', port=8080) 
