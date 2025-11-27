from flask import Flask, request, redirect, abort, url_for, render_template, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import smtplib
import ssl
import getpass
from email.message import EmailMessage
import time
import os
import re
import random
import threading
import docker

# Initialize Docker client
docker_client = docker.from_env()

# Define Functions
def hash_string(passwd):
    return hashlib.sha256(passwd.encode('utf-8')).hexdigest()

def gen_Token(user, time):
    return hash_string(f"{hash_string(user)}{str(int(time))}")

def delete_expired():
    accounts = sqlite3.connect("accounts.db")
    cur = accounts.cursor()
    cur.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
    cur.execute("DELETE FROM auth WHERE expires<?", (time.time(),))
    accounts.commit()
    cur.close()

def get_accounts():
    accounts = sqlite3.connect("accounts.db")
    cur = accounts.cursor()
    res = cur.execute("SELECT * FROM accounts")
    final = res.fetchall()
    cur.close()
    return final

def get_Amount_of_Users():
    accounts = sqlite3.connect("accounts.db")
    cur = accounts.cursor()
    res = cur.execute("SELECT * FROM accounts")
    final = res.fetchall()
    cur.close()
    return len(final)

def user_exists(user):
    accounts = sqlite3.connect("accounts.db")
    cur = accounts.cursor()
    res = cur.execute("SELECT user FROM accounts")
    final = res.fetchall()
    for x in final:
        if user in x:
            cur.close()
            return True
    cur.close()
    return False

def in_auth(user):
    accounts = sqlite3.connect("accounts.db")
    cur = accounts.cursor()
    res = cur.execute("SELECT user FROM auth")
    final = res.fetchall()
    for x in final:
        if user in x:
            cur.close()
            return True
    cur.close()
    return False


# Initialize the accounts database
acc_db = sqlite3.connect("accounts.db")
acc_cur = acc_db.cursor()
acc_cur.execute("CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, password TEXT NOT NULL)")
acc_cur.execute("CREATE TABLE IF NOT EXISTS sessions(user TEXT NOT NULL, token TEXT NOT NULL, expires)")
acc_cur.execute("CREATE TABLE IF NOT EXISTS auth(user TEXT NOT NULL, password_hash TEXT NOT NULL, expires)")
acc_cur.execute("CREATE TABLE IF NOT EXISTS containers(id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, build_status TEXT NOT NULL, uptime REAL)")

res = acc_cur.execute("SELECT * FROM accounts")
if len(res.fetchall()) == 0:
    admin_password = hash_string(getpass.getpass("Admin Password: "))
    acc_cur.execute(f"""
        INSERT INTO accounts (user, password) VALUES
        ("admin", "{admin_password}")
    """)
    acc_db.commit()

acc_db.close()

# Initialize Flask App
app = Flask(__name__)
CORS(app)

@app.route("/", methods=['POST', 'GET'])
def default():
    return "Welcome to the Silk Dev Portal Root"

@app.route("/validate/", methods=['POST'])
def validate():
    data = request.json
    token = data["token"]

    if not token:
        return {
            "status":"No Token Requested"
        }, 400
    
    print("Requested Token:" + token)

    db = sqlite3.connect("accounts.db")
    cur = db.cursor()
    res = cur.execute("SELECT * FROM sessions WHERE token=?", (token,))
    final = res.fetchone()
    db.close()

    if final == None:
        return {
            "status":"Invalid Token"
        }, 403
    
    print("Required Token:" + final[1])

    if final[1] == token and time.time() < final[2]:
        return {
            "status":"Success",
            "username":final[0]
        }
    else:
        return {
            "status":"Expired Token"
        }, 403

@app.route("/accounts/", methods=['GET'])
def accounts():
    account_id = request.args.get("id")
    if account_id != None:
        try:
            account_id = int(account_id)
        except:
            return {
                "status":"Account ID is in an invalid format"
            }, 400
        
        db = sqlite3.connect("accounts.db")
        cur = db.cursor()
        res = cur.execute("SELECT * FROM accounts WHERE id=?", (account_id,))
        account = res.fetchone()

        if account != None:
            return {
                "status":"Success",
                "account":account
            }
        else:
            return {
                "status":"User not found"
            }, 404
    else:
        return {
            "status":"Success",
            "account":get_accounts()
        }
    
@app.route("/accounts/len", methods=['GET'])
def accounts_len():
    db = sqlite3.connect("accounts.db")
    cur = db.cursor()
    res = cur.execute("SELECT COUNT(*) FROM accounts")
    accountslen = res.fetchone()

    return {
        "status":"Success",
        "accountslen":accountslen[0]
    }
        
@app.route("/login/", methods=['POST'])
def login():
    delete_expired()
    data = request.json
    username = data["user"]
    password = data["password"]

    if in_auth(username):
        return {
            "status":"Authentication in progress"
        }, 403

    if user_exists(username):
        db = sqlite3.connect("accounts.db")
        cur = db.cursor()
        res = cur.execute("SELECT password FROM accounts WHERE user=?", (username,))
        final = res.fetchone()
        print(f"Request from {username} at Login")

        if final[0] == hash_string(password):
            res = cur.execute("SELECT * FROM sessions WHERE user=?", (username,))
            final = res.fetchone()

            current_time = time.time()
            expires = current_time + 86400
            token = gen_Token(username, current_time)

            if final == None or time.time() > final[2]:
                cur.execute("DELETE FROM sessions WHERE user=?", (username,))
                cur.execute("INSERT INTO sessions VALUES (?,?,?)", (username, token, expires))
                db.commit()
                print(f"Generated token for {username}")

            cur.close()
            print(f"{username} logged in.")
            return {
                "status":"Success",
                "token":token
            }
        else:
            return {
                "status":"Wrong login credentials"
            }, 403
    else:
        return {
            "status":"No such account"
        }, 404

@app.route("/register/", methods=['POST'])
def register():
    delete_expired()
    data = request.json
    username = data["user"]
    password = data["password"]

    if username and password:
        if user_exists(username):
            return {
                "status":"Account already exists"
            }, 400
        if in_auth(username):
            return {
                "status":"Account already in authentication waitlist"
            }, 400
        if len(password) < 5:
            return {
                "status":"Password should include at least 5 characters"
            }, 400

        print(f"Request from {username} at Register")

        current_time = time.time()
        expires = current_time + 600

        # Save authentication code and info into database
        db = sqlite3.connect("accounts.db")
        cur = db.cursor()
        res = cur.execute("SELECT * FROM auth WHERE user=?", (username,))

        cur.execute("INSERT INTO auth (user, password_hash, expires) VALUES (?,?,?)", (username, hash_string(password), expires))
        db.commit()
        db.close()

        return {
            "status":"Success"
        }

    else:
        return {
            "status":"Login credentials are missing"
        }, 400
    
@app.route("/register/add", methods=['POST'])
def create_account():
    delete_expired()
    data = request.json
    username = data["user"]
    req_ad_pass = data["password"]

    if username and admin_password:
        if not in_auth(username):
            return {
                "status":"Account was not registered"
            }, 400
        if hash_string(req_ad_pass) != admin_password:
            return {
                "status":"Admin Password incorrect"
            }, 403
        
        # Get password hash from the auth table
        db = sqlite3.connect("accounts.db")
        cur = db.cursor()
        res = cur.execute("SELECT * FROM auth WHERE user=?", (username,))
        user_pass = res.fetchone()

        print(user_pass)
        
        # Add account to the database
        cur.execute("INSERT INTO accounts (user, password_hash) VALUES (?,?)", (username, hash_string(user_pass)))
        db.commit()
        db.close()

        return {
            "status":"Success"
        }
        
    else:
        return {
            "status":"Credentials are missing"
        }, 400

@app.route("/api/containers", methods=['GET'])
def list_containers():
    db = sqlite3.connect("accounts.db")
    cur = db.cursor()
    res = cur.execute("SELECT * FROM containers")
    containers = res.fetchall()
    print(containers)
    db.close()
    return jsonify(containers)

@app.route("/api/containers/create", methods=['POST'])
def create_container():
    container_name = f"silkos-build-container-{random.randint(1000, 9999)}"
    try:
        container = docker_client.containers.run("ubuntu:24.04", detach=True, name=container_name, tty=True)
        db = sqlite3.connect("accounts.db")
        cur = db.cursor()
        cur.execute("INSERT INTO containers VALUES (?,?,?,?,?)", (container.id, container.name, container.status, "Inactive", time.time()))
        db.commit()
        db.close()
        return jsonify({"status": "Success", "container_id": container.id})
    except docker.errors.APIError as e:
        return jsonify({"status": "Error", "message": str(e)}), 500

@app.route("/api/containers/<container_id>", methods=['DELETE'])
def delete_container(container_id):
    try:
        container = docker_client.containers.get(container_id)
        container.remove(force=True)
        db = sqlite3.connect("accounts.db")
        cur = db.cursor()
        cur.execute("DELETE FROM containers WHERE id=?", (container_id,))
        db.commit()
        db.close()
        return jsonify({"status": "Success"})
    except docker.errors.NotFound:
        return jsonify({"status": "Error", "message": "Container not found"}), 404
    except docker.errors.APIError as e:
        return jsonify({"status": "Error", "message": str(e)}), 500

@app.route("/api/containers/<container_id>/build", methods=['POST'])
def build_container(container_id):
    try:
        container = docker_client.containers.get(container_id)
        log_path = os.path.join(app.root_path, "tmp", f"{container_id}.log")

        # Ensure the tmp directory exists
        os.makedirs(os.path.join(app.root_path, "tmp"), exist_ok=True)

        # Run the build script in the background
        def run_build():
            with open(log_path, "w") as log_file:
                try:
                    db = sqlite3.connect("accounts.db")
                    cur = db.cursor()
                    cur.execute("UPDATE containers SET build_status='Active' WHERE id=?", (container_id,))
                    db.commit()
                    db.close()

                    # Stream the output of the command
                    exit_code, stream = container.exec_run(
                        "sh -c 'apt-get update && apt-get install -y sudo git build-essential cmake curl libmpfr-dev libmpc-dev libgmp-dev e2fsprogs ninja-build qemu-system-gui qemu-system-x86 qemu-utils ccache rsync unzip texinfo libssl-dev zlib1g-dev && useradd -m -s /bin/bash builder && usermod -aG sudo builder && echo \"builder ALL=(ALL) NOPASSWD: ALL\" >> /etc/sudoers && su builder -c \"git clone https://github.com/CommandCrafterx/SilkOS.git /home/builder/SilkOS && cd /home/builder/SilkOS && ./Meta/silkos.sh run\"'",
                        stream=True,
                        user='root'
                    )


                    for chunk in stream:
                        log_file.write(chunk.decode('utf-8'))
                        log_file.flush()

                    db = sqlite3.connect("accounts.db")
                    cur = db.cursor()
                    if exit_code == 0:
                        cur.execute("UPDATE containers SET build_status='Success' WHERE id=?", (container_id,))
                    else:
                        cur.execute("UPDATE containers SET build_status='Failed' WHERE id=?", (container_id,))
                    db.commit()
                    db.close()
                except Exception as e:
                    log_file.write(str(e))
                    db = sqlite3.connect("accounts.db")
                    cur = db.cursor()
                    cur.execute("UPDATE containers SET build_status='Failed' WHERE id=?", (container_id,))
                    db.commit()
                    db.close()

        threading.Thread(target=run_build).start()

        return jsonify({"status": "Success", "message": "Build started"})
    except docker.errors.NotFound:
        return jsonify({"status": "Error", "message": "Container not found"}), 404
    except docker.errors.APIError as e:
        return jsonify({"status": "Error", "message": str(e)}), 500

@app.route("/api/containers/<container_id>/logs", methods=['GET'])
def container_logs(container_id):
    log_path = os.path.join(app.root_path, "tmp", f"{container_id}.log")
    if os.path.exists(log_path):
        with open(log_path, "r") as log_file:
            return jsonify({"logs": log_file.read()})
    else:
        return jsonify({"logs": ""})

@app.route("/manage")
def manage():
    return render_template("manage.html")

@app.errorhandler(404)
def page_not_found(error):
    return {
        "status":"Not found"
    }, 404
