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
def index():
    return render_template('index.html')


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

    output = ATTACK_LABELS.get(pred_val, f'Attack Detected, Class: {pred_val}')
    return render_template('prediction.html', output=output)


if __name__ == "__main__":
    app.run(debug=True)

