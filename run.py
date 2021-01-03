from covidtrackapi import socketio, app
from flask import send_from_directory, make_response
from flask_apscheduler import APScheduler
import math
from covidtrackapi.main.utils import fetchWorldUpdates

# Add th app scheduler
scheduler = APScheduler()

# app = create_app()

# Initiate the sw and manifest


if __name__ == "__main__":
    scheduler.add_job(id='Scheduled Task', func=fetchWorldUpdates, trigger='interval', seconds=3600)
    
    scheduler.start()
    
    socketio.run(app, debug=True, port=5800, host="0.0.0.0")