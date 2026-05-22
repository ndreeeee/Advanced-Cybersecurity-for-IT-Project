"""
Legacy entrypoint — Trust Score Engine spostato in trust_engine.py (MongoDB + Splunk).

Per avviare il motore SIEM:
  python trust_engine.py
  oppure container trust-engine nel docker-compose.
"""

from trust_engine import poll_splunk_and_update, splunk_login

if __name__ == "__main__":
    key = splunk_login()
    if key:
        poll_splunk_and_update()
