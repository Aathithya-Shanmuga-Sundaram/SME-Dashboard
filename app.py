import random
import csv
import io
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, Response, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mecs-realism-v1'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mecs_realistic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    os_type = db.Column(db.String(50))
    role = db.Column(db.String(50))
    risk_score = db.Column(db.Integer, default=0)
    vulns = db.relationship('Vulnerability', backref='asset', lazy=True, cascade="all, delete")

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20))
    name = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ORGANIC RISK ENGINE ---
VULN_DB = {
    "Windows": [("CVE-2019-0708", "BlueKeep RDP", "Critical"), ("CVE-2021-1675", "PrintNightmare", "High")],
    "Linux": [("CVE-2014-6271", "Shellshock", "Critical"), ("CVE-2021-3156", "Sudo Baron Samedit", "High")],
    "Generic": [("CVE-2021-44228", "Log4j RCE", "Critical"), ("WEAK-AUTH", "Weak Password", "Medium"), ("INFO-LEAK", "Banner Grabbing", "Low")]
}

def calculate_organic_risk(vulns):
    if not vulns: return 0
    
    score = 0
    highest_severity = "Low"
    
    for v in vulns:
        # Add varied weights per vulnerability
        if v.severity == "Critical":
            score += random.randint(22, 35) # e.g., 27, 34
            highest_severity = "Critical"
        elif v.severity == "High":
            score += random.randint(14, 23) # e.g., 18, 21
            if highest_severity != "Critical": highest_severity = "High"
        elif v.severity == "Medium":
            score += random.randint(7, 13)  # e.g., 9, 11
        elif v.severity == "Low":
            score += random.randint(2, 6)   # e.g., 3, 5
            
    # Apply Realistic Floors with Jitter
    # (A Critical server shouldn't be 30, it should be naturally high like 83 or 91)
    if highest_severity == "Critical":
        # Ensure score is at least between 76 and 88, then add the rest
        min_score = random.randint(76, 88)
        score = max(score, min_score)
    elif highest_severity == "High":
        # Ensure score is at least between 48 and 62
        min_score = random.randint(48, 62)
        score = max(score, min_score)

    # Add organic noise (simulate environmental factors)
    noise = random.randint(-3, 4)
    final_score = score + noise
    
    return min(max(final_score, 0), 100) # Clamp 0-100

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid Credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    assets = Asset.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(6).all()
    
    total_assets = len(assets)
    # High Risk > 50
    high_risk_assets = len([a for a in assets if a.risk_score > 50])
    avg_score = sum([a.risk_score for a in assets]) / total_assets if total_assets > 0 else 0

    # Chart Data: Classify Assets by their specific Score
    chart_data = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for asset in assets:
        if asset.risk_score >= 75: chart_data['Critical'] += 1
        elif asset.risk_score >= 50: chart_data['High'] += 1
        elif asset.risk_score >= 20: chart_data['Medium'] += 1
        else: chart_data['Low'] += 1
        
    return render_template('dashboard.html', assets=assets, logs=logs, 
                           kpis={'total': total_assets, 'high_risk': high_risk_assets, 'avg': round(avg_score, 1)},
                           chart_data=chart_data, user=current_user)

@app.route('/add_asset', methods=['POST'])
@login_required
def add_asset():
    name = request.form.get('name')
    ip = request.form.get('ip')
    os_type = request.form.get('os_type')
    role = request.form.get('role')
    new_asset = Asset(name=name, ip_address=ip, os_type=os_type, role=role)
    db.session.add(new_asset)
    db.session.commit()
    perform_scan(new_asset.id)
    db.session.add(AuditLog(action=f"Asset Onboarded: {name}"))
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/scan/<int:asset_id>')
@login_required
def scan_route(asset_id):
    perform_scan(asset_id)
    return redirect(url_for('index'))

def perform_scan(asset_id):
    asset = Asset.query.get(asset_id)
    Vulnerability.query.filter_by(asset_id=asset.id).delete()
    
    # Randomly select 1 to 4 vulnerabilities to create variety
    threats = VULN_DB.get(asset.os_type, []) + VULN_DB["Generic"]
    num_vulns = random.choices([0, 1, 2, 3], weights=[10, 40, 30, 20], k=1)[0]
    found = random.sample(threats, k=min(num_vulns, len(threats)))
    
    for cve, name, sev in found:
        db.session.add(Vulnerability(cve_id=cve, name=name, severity=sev, asset_id=asset.id))
    
    db.session.commit()
    
    # Calculate the organic score
    asset.risk_score = calculate_organic_risk(asset.vulns)
    db.session.commit()

@app.route('/report')
@login_required
def download_report():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', datetime.now().strftime("%Y-%m-%d %H:%M")])
    writer.writerow(['Asset Name', 'IP Address', 'Risk Score', 'Vuln Count'])
    for a in Asset.query.all():
        writer.writerow([a.name, a.ip_address, a.risk_score, len(a.vulns)])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-disposition": "attachment; filename=mecs_risk_report.csv"})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password='password'))
            db.session.commit()
    app.run(debug=True)