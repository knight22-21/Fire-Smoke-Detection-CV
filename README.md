# Fire and Smoke Detection System

This is a web-based Fire and Smoke Detection System built using YOLOv8 for real-time object detection, Flask as the backend framework, and SQLite for user management and logging. The system allows authenticated users to upload images or videos, monitor live camera or IP camera feeds, and receive alerts in case of fire detection.

## Features

* User authentication with role-based access (Admin/User)
* Login, registration, and password reset support
* YOLOv8-based fire and smoke detection
* Support for image and video file uploads
* Real-time webcam and IP camera monitoring
* Email alerts upon fire detection
* SQLite database for storing user and detection logs
* Admin dashboard for viewing activity and detection history
* Theme toggle (Light/Dark mode)

## Tech Stack

* **Frontend:** HTML, CSS, Bootstrap 5, JavaScript
* **Backend:** Flask (Python)
* **Database:** SQLite
* **Computer Vision:** YOLOv8 (Ultralytics)


## Installation

1. **Clone the Repository**

```bash
git clone https://github.com/knight22-21/Fire-Smoke-Detection-CV.git
cd fire-detection-system
```

2. **Create a Virtual Environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install Requirements**

```bash
pip install -r requirements.txt
```

4. **Download YOLOv8 Weights**

Make sure you have YOLOv8 weights (`yolov8s.pt`) downloaded and placed in the appropriate location or configured in `yolo_inference.py`.

5. **Run the Application**

```bash
python app.py
```

The application will run on `http://127.0.0.1:5000/`

## Usage

* Visit the homepage and register a new user or log in if you already have an account.
* Upload an image/video or switch to the live camera feed to begin detection.
* If fire or smoke is detected, an email alert is triggered and the event is logged.
* Admins can view all detection logs from the dashboard.

## Security Notes

* Passwords are stored using hashing for user security.
* Sessions are securely managed using Flask sessions.
* Input validations are enforced in both frontend and backend.

