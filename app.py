import os
import shutil
import smtplib
import subprocess
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from email.message import EmailMessage
from dotenv import load_dotenv
from ultralytics import YOLO
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Response
import cv2
import time
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from datetime import datetime


# Load environment variables from .env file
load_dotenv()

# Email configuration
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")

# Flask app setup
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'static/outputs'

# Flask-Mail configuration
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False') == 'True'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


mail = Mail(app)

app.secret_key = os.getenv("SECRET_KEY")

# Ensure upload/output folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Load YOLOv8 model
model = YOLO("models/best.pt")


# Alert settings
last_alert_time = 0
ALERT_COOLDOWN = 60  # seconds between emails

# Generate frames from video stream and perform detection
def generate_live_frames(user_id, stream_url=None):
    global last_alert_time


    cap = cv2.VideoCapture(stream_url if stream_url else 0)

    while True:
        success, frame = cap.read()
        if not success:
            print("Failed to capture frame from stream.")
            break

        results = model(frame)
        annotated_frame = results[0].plot()


        detections = []
        for r in results:
            if r.boxes is not None:
                for box in r.boxes:
                    cls_id = int(box.cls[0])
                    class_name = model.names[cls_id]
                    detections.append(class_name)

        fire_detected = "fire" in detections
        smoke_detected = "smoke" in detections

        if (fire_detected or smoke_detected) and (time.time() - last_alert_time > ALERT_COOLDOWN):
            send_email_alert_from_live(user_id, detections)
            last_alert_time = time.time()

        _, buffer = cv2.imencode('.jpg', annotated_frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    cap.release()


@app.route('/start_ip_feed', methods=['POST'])
def start_ip_feed():
    if 'username' not in session:
        return redirect(url_for('login'))

    ip_url = request.form['ip_url'].strip()
    session['ip_url'] = ip_url

    return redirect(url_for('ip_feed'))

@app.route('/ip_feed')
def ip_feed():
    user_id = session.get('user_id')
    ip_url = session.get('ip_url')

    return Response(generate_live_frames(user_id, ip_url),
                    mimetype='multipart/x-mixed-replace; boundary=frame')



@app.route('/live')
def live():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('live.html', username=session['username'])

@app.route('/video_feed')
def video_feed():
    user_id = session.get('user_id')
    return Response(generate_live_frames(user_id),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


# Send email alert based on live detection
def send_email_alert_from_live(user_id, detections):
    conn = sqlite3.connect("fire_alerts.db")
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        print("User email not found.")
        return

    user_email = row[0]

    msg = EmailMessage()
    msg["Subject"] = " Live Fire/Smoke Alert Detected!"
    msg["From"] = EMAIL_SENDER
    msg["To"] = user_email

    fire_count = detections.count("fire")
    smoke_count = detections.count("smoke")

    msg.set_content(f"""
    Real-Time Alert!

    The live feed has detected:
     Fire instances: {fire_count}
     Smoke instances: {smoke_count}

    Stay safe!
    """)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("📧 Live email alert sent.")
    except Exception as e:
        print("Live email failed:", e)

# Convert uploaded video to MP4 format using ffmpeg
def convert_to_mp4(input_path, output_path):
    """Convert the video to MP4 format using ffmpeg"""
    command = [
        "ffmpeg",
        "-y",
        "-i", input_path,
        "-vcodec", "libx264",
        "-acodec", "aac",
        "-strict", "experimental",
        output_path
    ]
    subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Send email alert for uploaded video
def send_email_alert(video_path, detections):

    """Send an email alert if fire or smoke is detected"""
    user_id = session.get('user_id')

    conn = sqlite3.connect("fire_alerts.db")
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        print("User email not found.")
        return

    user_email = row[0]  # Receiver email
    msg = EmailMessage()
    msg["Subject"] = " Fire Alert Detected in Uploaded Video!"
    msg["From"] = EMAIL_SENDER
    msg["To"] = user_email

    detected_classes = [d['class'] for d in detections]
    fire_count = detected_classes.count("fire")

    msg.set_content(f"""
    Alert!

    The AI Fire & Smoke Detection system has detected FIRE in the uploaded video.
    Number of fire instances: {fire_count}

    Immediate attention is recommended.

    -- Auto-generated from Fire Detector
    """)

    with open(video_path, 'rb') as f:
        file_data = f.read()
        msg.add_attachment(file_data, maintype='video', subtype='mp4', filename=os.path.basename(video_path))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(" Email alert sent.")
    except Exception as e:
        print("Failed to send email:", e)

# Log detection result into database
def log_detection(filename, detected_classes, fire_count, smoke_count, email_sent):
    user_id = session.get('user_id')
    conn = sqlite3.connect('fire_alerts.db')
    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO detections (user_id, filename, detected_classes, fire_count, smoke_count, email_sent)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
        filename,
        ', '.join(detected_classes),
        fire_count,
        smoke_count,
        email_sent
    ))
    conn.commit()
    conn.close()


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm_password']
        role = request.form['role'].strip().lower()

        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for('register'))

        hashed = generate_password_hash(password)

        try:
            conn = sqlite3.connect('fire_alerts.db')
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                        (username, email, hashed, role))
            conn.commit()
            conn.close()
            flash("Registered successfully.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or Email already exists.")
            return redirect(url_for('register'))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        selected_role = request.form['role'].strip().lower()

        conn = sqlite3.connect('fire_alerts.db')
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            db_role = user[3].strip().lower()

            if db_role != selected_role:
                flash("Selected role does not match your registered role.")
                return redirect(url_for('login'))

            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = db_role

            flash("Logged in successfully.")

            if db_role == "admin":
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))  # Regular user

        else:
            flash("Invalid credentials.")
            return redirect(url_for('login'))

    return render_template("login.html")



@app.route('/logout', methods=['POST'])
def logout():
    """User logout route"""
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash("Logged out.")
    return redirect(url_for('login'))


with app.app_context():
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

# Generate token function
def generate_token(email):
    return s.dumps(email, salt='password-reset-salt')

# Verify token function
def verify_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=expiration)
        return email
    except Exception as e:
        return None


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()

        # Check if the email exists in the database
        conn = sqlite3.connect('fire_alerts.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            token = generate_token(email)
            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Request",
                          sender=EMAIL_SENDER,
                          recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_link}"

            try:
                mail.send(msg)
                flash("Password reset link sent to your email.")
            except Exception as e:
                print("Error sending reset email:", e)
                flash("Failed to send reset email.")
            return redirect(url_for('login'))

        flash("Email not found.")
        return redirect(url_for('forgot_password'))

    return render_template("forgot_password.html")


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token)
    if email is None:
        flash("The reset link is invalid or expired.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for('reset_password', token=token))

        hashed_password = generate_password_hash(new_password)

        conn = sqlite3.connect('fire_alerts.db')
        cursor = conn.cursor()


        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            user_id = user[0]
            cursor.execute("UPDATE users SET password = ? WHERE id = ?",
                           (hashed_password, user_id))
            conn.commit()
            conn.close()
            flash("Password successfully reset. Please log in.")
            return redirect(url_for('login'))
        else:
            conn.close()
            flash("User not found.")
            return redirect(url_for('login'))

    return render_template("reset_password.html")

@app.route('/detect', methods=['POST'])
def detect():
    """YOLOv8 detection route"""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    filename = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(input_path)

    # Run YOLOv8 detection
    results = model.predict(source=input_path, save=True, conf=0.25)
    output_dir = results[0].save_dir

    output_file = next((f for f in os.listdir(output_dir)
                        if f.lower().endswith(('.jpg', '.jpeg', '.png', '.mp4', '.avi'))), None)
    if not output_file:
        return jsonify({"error": "Processed file not found."}), 500

    output_path = os.path.join(output_dir, output_file)

    # Convert to .mp4
    if output_file.endswith('.avi'):
        mp4_name = os.path.splitext(output_file)[0] + '.mp4'
        final_output_path = os.path.join(OUTPUT_FOLDER, mp4_name)
        convert_to_mp4(output_path, final_output_path)
        output_url = f"/static/outputs/{mp4_name}"
    else:
        final_output_path = os.path.join(OUTPUT_FOLDER, output_file)
        shutil.move(output_path, final_output_path)
        output_url = f"/static/outputs/{output_file}"

    # Prepare detections
    detections = []
    fire_count = 0
    smoke_count = 0
    detected_classes = []

    for r in results:
        if r.boxes is not None:
            for box in r.boxes:
                cls_id = int(box.cls[0])
                conf = float(box.conf[0])
                detection = {
                    "class": model.names[cls_id],
                    "confidence": round(conf, 2)
                }
                detections.append(detection)
                detected_classes.append(detection["class"])

                if detection["class"] == "fire":
                    fire_count += 1
                elif detection["class"] == "smoke":
                    smoke_count += 1

    email_sent = False
    if fire_count > 0 or smoke_count > 0:
        send_email_alert(final_output_path, detections)
        email_sent = True

    log_detection(
        filename=filename,
        detected_classes=detected_classes,
        fire_count=fire_count,
        smoke_count=smoke_count,
        email_sent=email_sent
    )

    return jsonify({
        "output_url": output_url,
        "detections": detections
    })


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    conn = sqlite3.connect('fire_alerts.db')
    cursor = conn.cursor()

    if start_date and end_date:
        cursor.execute('''
            SELECT id, filename, detected_classes, fire_count, smoke_count, email_sent, timestamp 
            FROM detections 
            WHERE user_id = ? AND DATE(timestamp) BETWEEN DATE(?) AND DATE(?)
            ORDER BY timestamp DESC
        ''', (user_id, start_date, end_date))
    else:
        cursor.execute('''
            SELECT id, filename, detected_classes, fire_count, smoke_count, email_sent, timestamp 
            FROM detections 
            WHERE user_id = ? 
            ORDER BY timestamp DESC
        ''', (user_id,))

    rows = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", detections=rows)


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('login'))

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    conn = sqlite3.connect('fire_alerts.db')
    cursor = conn.cursor()


    if start_date and end_date:
        cursor.execute('''
            SELECT d.id, u.username, u.email, d.filename, d.detected_classes, d.fire_count, 
                   d.smoke_count, d.email_sent, d.timestamp 
            FROM detections d
            JOIN users u ON d.user_id = u.id
            WHERE DATE(d.timestamp) BETWEEN DATE(?) AND DATE(?)
            ORDER BY d.timestamp DESC
        ''', (start_date, end_date))
    else:

        cursor.execute('''
            SELECT d.id, u.username, u.email, d.filename, d.detected_classes, d.fire_count, 
                   d.smoke_count, d.email_sent, d.timestamp 
            FROM detections d
            JOIN users u ON d.user_id = u.id
            ORDER BY d.timestamp DESC
        ''')

    rows = cursor.fetchall()
    conn.close()

    return render_template("admin_dashboard.html", detections=rows)



@app.route('/home')
def home():
    """Render the YOLOv8 detection form for authenticated users"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("home.html", username=session['username'])

@app.route('/')
def index():
    """Landing page with Login/Register options"""
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)