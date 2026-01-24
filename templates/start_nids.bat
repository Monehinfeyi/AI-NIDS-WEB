@echo off
echo 🛡️ Starting AI-NIDS IPS and Maintenance Janitor...
start cmd /k ".venv\Scripts\activate && python app.py"
start cmd /k ".venv\Scripts\activate && python maintenance.py"
echo ✅ Both systems are running. Dashboard at http://localhost:5000