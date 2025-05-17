import sqlite3

conn = sqlite3.connect('fire_alerts.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filename TEXT,
    detected_classes TEXT,
    fire_count INTEGER,
    smoke_count INTEGER,
    email_sent BOOLEAN,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

conn.commit()
conn.close()
print("✅ Database initialized.")
