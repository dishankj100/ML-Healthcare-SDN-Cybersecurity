import os
import random
import smtplib
import sqlite3
import warnings
from email.message import EmailMessage
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, render_template

warnings.filterwarnings('ignore')

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__, template_folder='Templates', static_folder='Static', static_url_path='/static')

# Mail configuration via environment variables
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')

def init_db():
    """Ensure database table exists for clean clones without committing signup.db"""
    con = sqlite3.connect('signup.db')
    cur = con.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS info(
            user varchar(250),
            email varchar(250),
            password varchar(250),
            mobile int,
            name varchar(250)
        )
    ''')
    con.commit()
    con.close()

init_db()

# Load the trained model at startup
MODEL_PATH = 'model.sav'
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"Warning loading {MODEL_PATH}: {e}")

ATTACK_LABELS = {
    0: 'There is an Attack Detected, Attack Type is BruteForce!',
    1: 'There is an Attack Detected, Attack Type is CMD!',
    2: 'There is an No Attack Detected, it is Normal!',
    3: 'There is an Attack Detected, Attack Type is Probe!',
    4: 'There is an Attack Detected, Attack Type is Smaba!',
    5: 'There is an Attack Detected, Attack Type is SQLInjection!',
    6: 'There is an Attack Detected, Attack Type is TCPDDOS!',
    7: 'There is an Attack Detected, Attack Type is UDPDDOS!',
    8: 'There is an Attack Detected, Attack Type is VNC!'
}


@app.route('/')
@app.route('/soc')
def index():
    return render_template('soc.html')



@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/logon')
def logon():
    return render_template('signup.html')


@app.route('/login')
def login():
    return render_template('signin.html')


@app.route('/home1')
def home1():
    return render_template('home.html')


@app.route("/signup")
def signup():
    global otp, username, name, email, number, password
    username = request.args.get('user', '')
    name = request.args.get('name', '')
    email = request.args.get('email', '')
    number = request.args.get('mobile', '')
    password = request.args.get('password', '')
    otp = random.randint(1000, 5000)
    print(f"Generated OTP: {otp}")

    # Attempt to send email via SMTP if credentials are configured; otherwise fallback cleanly
    if MAIL_USERNAME and MAIL_PASSWORD and email:
        try:
            msg = EmailMessage()
            msg.set_content("Your OTP is : " + str(otp))
            msg['Subject'] = 'OTP'
            msg['From'] = MAIL_USERNAME
            msg['To'] = email

            s = smtplib.SMTP('smtp.gmail.com', 587, timeout=5)
            s.starttls()
            s.login(MAIL_USERNAME, MAIL_PASSWORD)
            s.send_message(msg)
            s.quit()
        except Exception as e:
            print(f"Notice: SMTP delivery failed ({e}). Proceed with OTP: {otp}")
    else:
        print(f"SMTP not configured or offline. Proceed with OTP: {otp}")

    return render_template("val.html", otp_hint=otp)


@app.route('/predict1', methods=['POST'])
def predict1():
    global otp, username, name, email, number, password
    if request.method == 'POST':
        message = request.form.get('message', '')
        print(f"Submitted OTP: {message}, Expected OTP: {otp}")
        try:
            if message and int(message) == int(otp):
                print("OTP verified successfully!")
                con = sqlite3.connect('signup.db')
                cur = con.cursor()
                cur.execute("insert into `info` (`user`,`email`, `password`,`mobile`,`name`) VALUES (?, ?, ?, ?, ?)",
                            (username, email, password, number, name))
                con.commit()
                con.close()
                return render_template("signin.html")
        except (ValueError, TypeError):
            pass
    return render_template("signup.html")


@app.route("/signin")
def signin():
    mail1 = request.args.get('user', '')
    password1 = request.args.get('password', '')
    con = sqlite3.connect('signup.db')
    cur = con.cursor()
    cur.execute("select `user`, `password` from info where `user` = ? AND `password` = ?", (mail1, password1,))
    data = cur.fetchone()
    con.close()

    if data is None:
        return render_template("signin.html")
    elif mail1 == str(data[0]) and password1 == str(data[1]):
        return render_template("home.html")
    else:
        return render_template("signin.html")


@app.route("/notebook")
def notebook1():
    return render_template("Notebook.html")


# ============================================================================
# HEALTHGUARD AI - SOC REST APIS & ADVANCED MODULES
# ============================================================================
try:
    from soc_engine import (
        soc_engine,
        SCENARIOS,
        HOSPITAL_TOPOLOGY,
        ACTUAL_EVALUATION_RESULTS,
        ATTACK_CLASSES,
        FEATURE_NAMES
    )
except ImportError as e:
    print(f"Warning importing soc_engine: {e}")
    soc_engine = None


@app.route('/soc')
def soc_dashboard():
    """Main HealthGuard AI Security Operations Centre interface."""
    return render_template('soc.html')


@app.route('/classic')
def classic_index():
    """Preserved original landing page."""
    return render_template('index.html')


@app.route('/api/stats')
def api_stats():
    """Get real-time threat KPIs and telemetry counters."""
    if soc_engine:
        return jsonify(soc_engine.get_threat_stats())
    return jsonify({'error': 'SOC Engine unavailable'}), 500


@app.route('/api/scenarios')
def api_scenarios():
    """Get predefined attack and normal scenarios from real dataset samples."""
    return jsonify(SCENARIOS)


@app.route('/api/predict_soc', methods=['POST'])
@app.route('/api/predict', methods=['POST'])
def api_predict_soc():
    """
    Run real ML prediction on switch telemetry vector or predefined scenario.
    Returns prediction, genuine confidence, SHAP explanation, and incident ID.
    """
    if not soc_engine:
        return jsonify({'error': 'SOC Engine unavailable'}), 500

    data = request.get_json(silent=True) or {}
    scenario_id = data.get('scenario_id')
    features = data.get('features')
    source_ip = data.get('source_ip')
    dest_ip = data.get('dest_ip')
    asset_name = data.get('target_asset')

    if scenario_id and scenario_id in SCENARIOS:
        sc = SCENARIOS[scenario_id]
        features = sc['features']
        source_ip = source_ip or sc['source_ip']
        dest_ip = dest_ip or sc['dest_ip']
        asset_name = asset_name or sc['target_asset']
    elif not features or len(features) != 9:
        return jsonify({'error': 'Invalid request: provide scenario_id or 9 numeric features.'}), 400

    try:
        features_float = [float(x) for x in features]
        result = soc_engine.predict_flow(
            features_list=features_float,
            source_ip=source_ip,
            dest_ip=dest_ip,
            asset_name=asset_name,
            auto_create_incident=True
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/explain/global')
def api_explain_global():
    """Get global feature importances extracted from the trained model."""
    if soc_engine:
        return jsonify(soc_engine.get_global_feature_importance())
    return jsonify({'error': 'SOC Engine unavailable'}), 500


@app.route('/api/explain/local', methods=['POST'])
def api_explain_local():
    """Get individual SHAP explanation for a given flow vector."""
    if not soc_engine:
        return jsonify({'error': 'SOC Engine unavailable'}), 500

    data = request.get_json(silent=True) or {}
    features = data.get('features')
    pred_class = data.get('class_id', 0)

    if not features or len(features) != 9:
        return jsonify({'error': 'Provide 9 numeric features.'}), 400

    try:
        features_float = [float(x) for x in features]
        x_arr = np.array([features_float], dtype=np.float64)
        explanation = soc_engine.explain_prediction(x_arr, int(pred_class))
        return jsonify(explanation)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/incidents', methods=['GET'])
def api_incidents():
    """Get incident records from persistent SQLite database."""
    if not soc_engine:
        return jsonify([])
    status_filter = request.args.get('status')
    limit = int(request.args.get('limit', 50))
    return jsonify(soc_engine.get_incidents(limit=limit, status_filter=status_filter))


@app.route('/api/incidents/<incident_id>/action', methods=['POST'])
def api_incident_action(incident_id):
    """
    Execute simulated mitigation action (BLOCK_IP, RATE_LIMIT, ISOLATE_DEVICE, RESOLVE).
    Updates incident and generates audit log with simulated OpenFlow rule.
    """
    if not soc_engine:
        return jsonify({'error': 'SOC Engine unavailable'}), 500

    data = request.get_json(silent=True) or {}
    action_type = data.get('action', '').upper()
    operator = data.get('operator', 'SOC_Operator')

    result = soc_engine.execute_mitigation(incident_id, action_type, operator=operator)
    return jsonify(result)


@app.route('/api/audit-log')
def api_audit_log():
    """Get immutable audit trail of operator and automated mitigation actions."""
    if not soc_engine:
        return jsonify([])
    limit = int(request.args.get('limit', 50))
    return jsonify(soc_engine.get_audit_log(limit=limit))


@app.route('/api/topology')
def api_topology():
    """Get healthcare network topology with asset status and synthetic IPs."""
    return jsonify(HOSPITAL_TOPOLOGY)


@app.route('/api/evaluation')
def api_evaluation():
    """Get actual test-set evaluation results and benchmark comparison."""
    return jsonify(ACTUAL_EVALUATION_RESULTS)


@app.route('/api/reset_demo', methods=['POST'])
def api_reset_demo():
    """Reset incidents and audit log to initial demonstration baseline."""
    if not soc_engine:
        return jsonify({'error': 'SOC Engine unavailable'}), 500
    try:
        con = sqlite3.connect('signup.db')
        cur = con.cursor()
        cur.execute("DELETE FROM soc_incidents")
        cur.execute("DELETE FROM soc_audit_log")
        con.commit()
        con.close()
        soc_engine.seed_initial_incidents()
        return jsonify({'success': True, 'message': 'Demo database restored to baseline.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# PRESERVED ORIGINAL ROUTES & PREDICTION HANDLERS
# ============================================================================
@app.route('/predict', methods=['POST'])
def predict():
    global model
    if model is None:
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
        else:
            return render_template('prediction.html', output='Model file not found. Please ensure model.sav exists.')

    int_features = [float(x) for x in request.form.values()]
    print(f"Prediction input ({len(int_features)} features): {int_features}")
    final4 = np.array([int_features])
    prediction = model.predict(final4)
    pred_val = int(prediction[0]) if hasattr(prediction, '__len__') else int(prediction)

    # If malicious, also record in SOC database for integrated cross-module visibility
    if soc_engine and pred_val != 2:
        try:
            soc_engine.predict_flow(
                features_list=int_features,
                source_ip='192.168.1.100 (Single-Flow Tester)',
                dest_ip='10.0.1.15 (ICU Monitor)',
                asset_name='Manual Telemetry Tester',
                auto_create_incident=True
            )
        except Exception as e:
            print(f"Notice: Failed to auto-log single flow prediction: {e}")

    output = ATTACK_LABELS.get(pred_val, f'Attack Detected, Class: {pred_val}')
    return render_template('prediction.html', output=output)


if __name__ == "__main__":
    app.run(debug=True)


