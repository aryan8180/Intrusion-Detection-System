from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List
import sqlite3
import datetime

app = FastAPI()

# Database setup
def init_db():
    conn = sqlite3.connect('web_app/backend/alerts.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            description TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Set up templates directory
templates = Jinja2Templates(directory="web_app/frontend/templates")

# Serve the dashboard page
@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

# Alert model (for receiving alerts)
class Alert(BaseModel):
    source_ip: str
    destination_ip: str
    description: str
    timestamp: str

# Endpoint to receive an alert
@app.post("/alert/")
async def receive_alert(alert: Alert):
    conn = sqlite3.connect('web_app/backend/alerts.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO alerts (source_ip, destination_ip, description, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (alert.source_ip, alert.destination_ip, alert.description, alert.timestamp))
    conn.commit()
    conn.close()
    return {"message": "Alert received successfully"}

# Endpoint to fetch all alerts
@app.get("/alerts/", response_model=List[Alert])
async def get_alerts():
    conn = sqlite3.connect('web_app/backend/alerts.db')
    c = conn.cursor()
    c.execute('SELECT source_ip, destination_ip, description, timestamp FROM alerts')
    rows = c.fetchall()
    conn.close()
    return [Alert(source_ip=row[0], destination_ip=row[1], description=row[2], timestamp=row[3]) for row in rows]
