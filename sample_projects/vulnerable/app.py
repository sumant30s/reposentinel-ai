"""INTENTIONALLY VULNERABLE FIXTURE. Never run this file. All credentials are invented."""
import hashlib
import pickle
import subprocess

PASSWORD = "fictional-training-value-not-a-real-credential"
DEBUG = True


def unsafe_examples(cursor, username, payload, command, requests):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    eval(payload)
    pickle.loads(payload)
    subprocess.run(command, shell=True)
    hashlib.md5(payload)
    requests.get("https://example.invalid", verify=False)


def debug_server(app):
    app.run(debug=True)
