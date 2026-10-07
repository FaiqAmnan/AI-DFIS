from flask import Flask, abort, render_template, request, redirect, url_for, session

from sklearn.ensemble import IsolationForest

from werkzeug.security import check_password_hash, generate_password_hash

from werkzeug.utils import secure_filename

import os

import sqlite3

import hashlib
import re
from datetime import datetime, timedelta



app = Flask(__name__)

app.secret_key = "ai-dfis-secret-key"



DATABASE = os.path.join(app.root_path, "ai_dfis.db")

print("DATABASE PATH:", os.path.abspath(DATABASE))



def get_db_connection():



    conn = sqlite3.connect(DATABASE)



    conn.row_factory = sqlite3.Row



    return conn



def verify_user_password(stored_password, entered_password):

    """

    Verify a password whether the database contains:

    - a Werkzeug hashed password

    - or an old plaintext password

    """



    if not stored_password or entered_password is None:

        return False



    # First try the secure hashed password

    try:

        if check_password_hash(stored_password, entered_password):

            return True

    except (ValueError, TypeError):

        pass



    # Temporary compatibility for old accounts

    if stored_password == entered_password:

        return True



    return False



def init_database():



    conn = get_db_connection()



    conn.execute("""

        CREATE TABLE IF NOT EXISTS users (



            id INTEGER PRIMARY KEY AUTOINCREMENT,



            name TEXT NOT NULL,



            username TEXT UNIQUE NOT NULL,



            password TEXT NOT NULL,



            role TEXT NOT NULL



        )

    """)



    conn.execute("""

        CREATE TABLE IF NOT EXISTS evidence (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            filename TEXT NOT NULL,

            file_type TEXT,

            uploaded_by INTEGER,

            upload_date TEXT NOT NULL,

            status TEXT DEFAULT 'Uploaded',

            FOREIGN KEY (uploaded_by) REFERENCES users(id)

        )

    """)



    conn.execute("""

    CREATE TABLE IF NOT EXISTS investigations (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        case_id TEXT UNIQUE NOT NULL,

        case_name TEXT NOT NULL,

        description TEXT,

        status TEXT NOT NULL DEFAULT 'Investigating',

        created_by INTEGER,

        created_date TEXT NOT NULL,

        FOREIGN KEY (created_by) REFERENCES users(id)

    )

""")



        # Audit Trail table

    conn.execute("""

        CREATE TABLE IF NOT EXISTS audit_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            username TEXT,

            role TEXT,

            action TEXT NOT NULL,

            details TEXT,

            timestamp TEXT NOT NULL,

            FOREIGN KEY (user_id) REFERENCES users(id)

        )

    """)



    # Create default Admin account

    existing_admin = conn.execute(

        "SELECT * FROM users WHERE username = ?",

        ("admin",)

    ).fetchone()



    if existing_admin is None:



        conn.execute("""

            INSERT INTO users

            (name, username, password, role)



            VALUES (?, ?, ?, ?)

        """, (

            "System Administrator",

            "admin",

            generate_password_hash("admin123"),

            "Admin"

        ))





    # Create default Investigator account

    existing_investigator = conn.execute(

        "SELECT * FROM users WHERE username = ?",

        ("investigator01",)

    ).fetchone()



    if existing_investigator is None:



        conn.execute("""

            INSERT INTO users

            (name, username, password, role)



            VALUES (?, ?, ?, ?)

        """, (

            "Forensic Investigator",

            "investigator01",

            generate_password_hash("investigator123"),

            "Investigator"

        ))



        # Add investigation_id column to existing evidence table

    try:

        conn.execute("""

            ALTER TABLE evidence

            ADD COLUMN investigation_id INTEGER

        """)

        print("investigation_id column added to evidence table.")

    except sqlite3.OperationalError:

        pass



    conn.commit()



        # Add SHA-256 hash column to evidence table

    try:



        conn.execute("""

            ALTER TABLE evidence

            ADD COLUMN file_hash TEXT

        """)



        print("file_hash column added to evidence table.")



    except sqlite3.OperationalError:



        pass





    tables = conn.execute("""

        SELECT name

        FROM sqlite_master

        WHERE type = 'table'

        ORDER BY name

    """).fetchall()



    print("DATABASE TABLES:", [table["name"] for table in tables])



    conn.close()





def login_required():



    return "user_id" in session





def admin_required():



    return login_required() and session.get("role") == "Admin"



def log_action(action, details=""):

    try:

        conn = get_db_connection()



        conn.execute("""

            INSERT INTO audit_logs

            (user_id, username, role, action, details, timestamp)

            VALUES (?, ?, ?, ?, ?, ?)

        """, (

            session.get("user_id"),

            session.get("username"),

            session.get("role"),

            action,

            details,

            datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        ))



        conn.commit()

        conn.close()



    except Exception as e:

        print("Audit log error:", e)



@app.route("/audit-trail")

def audit_trail():



    conn = get_db_connection()



    if session.get("role") == "Admin":

        logs = conn.execute("""

            SELECT id, username, role, action, details, timestamp

            FROM audit_logs

            ORDER BY id DESC

        """).fetchall()



    else:

        logs = conn.execute("""

            SELECT id, username, role, action, details, timestamp

            FROM audit_logs

            WHERE user_id = ?

            ORDER BY id DESC

        """, (session.get("user_id"),)).fetchall()



    conn.close()



    return render_template(

        "audit_trail.html",

        logs=logs

    )



@app.before_request

def require_login():



    if request.endpoint in ["login", "static"]:

        return None



    if not login_required():

        return redirect(url_for("login"))



    return None





# Folder for uploaded evidence

UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")



# Create uploads folder automatically

if not os.path.exists(UPLOAD_FOLDER):

    os.makedirs(UPLOAD_FOLDER)


def get_analysis_filename():

    filename = request.args.get("file")

    if filename:

        if (
            os.path.basename(filename) != filename
            or not os.path.isfile(os.path.join(UPLOAD_FOLDER, filename))
        ):

            return None

        session["analysis_file"] = filename

        return filename

    filename = session.get("analysis_file")

    if (
        isinstance(filename, str)
        and os.path.basename(filename) == filename
        and os.path.isfile(os.path.join(UPLOAD_FOLDER, filename))
    ):

        return filename

    session.pop("analysis_file", None)

    return None


@app.route("/", methods=["GET", "POST"])

def login():



    if request.method == "POST":



        username = request.form.get("username", "").strip()

        password = request.form.get("password", "")



        if not username:

            return render_template(

                "login.html",

                error="Please enter your username."

            )



        if not password:

            return render_template(

                "login.html",

                error="Please enter your password."

            )



        conn = get_db_connection()



        user = conn.execute(

            """

            SELECT *

            FROM users

            WHERE username = ?

            """,

            (username,)

        ).fetchone()



        conn.close()



        if user is None:

            return render_template(

                "login.html",

                error="Invalid username or password"

            )



        password_valid = verify_user_password(

            user["password"],

            password

        )



        if not password_valid:

            return render_template(

                "login.html",

                error="Invalid username or password"

            )



        # Login successful

        session.clear()



        session["user_id"] = user["id"]

        session["username"] = user["username"]

        session["name"] = user["name"]

        session["role"] = user["role"]



        log_action(

            "Login",

            "User logged into the system"

        )



        return redirect(url_for("dashboard"))



    return render_template("login.html")



@app.route("/logout")

def logout():



    log_action(

        "Logout",

        "User logged out of the system"

    )



    session.clear()



    return redirect(url_for("login"))



@app.route("/dashboard")

def dashboard():



    conn = get_db_connection()



    total_investigations = conn.execute(

        "SELECT COUNT(*) FROM investigations"

    ).fetchone()[0]



    active_investigations = conn.execute(

        "SELECT COUNT(*) FROM investigations WHERE status != 'Completed'"

    ).fetchone()[0]



    recent_investigations = conn.execute("""

        SELECT case_id, case_name, status, created_date

        FROM investigations

        ORDER BY id DESC

        LIMIT 4

    """).fetchall()



    total_evidence = conn.execute(

        "SELECT COUNT(*) FROM evidence"

    ).fetchone()[0]



    uploaded_evidence = conn.execute(

        "SELECT COUNT(*) FROM evidence WHERE status = 'Uploaded'"

    ).fetchone()[0]



    evidence_files = conn.execute(

        "SELECT filename FROM evidence"

    ).fetchall()



    recent_activity = conn.execute("""

        SELECT action, details, timestamp

        FROM audit_logs

        ORDER BY id DESC

        LIMIT 4

    """).fetchall()



    conn.close()



    suspicious_activities = 0

    ai_anomalies = 0



    suspicious_words = [

        "failed",

        "suspicious",

        "unauthorized",

        "attack",

        "invalid",

        "multiple",

        "denied"

    ]



    for evidence in evidence_files:

        file_path = os.path.join(UPLOAD_FOLDER, evidence["filename"])



        if not os.path.isfile(file_path):

            continue



        try:

            with open(file_path, "r", encoding="utf-8") as file:

                log_content = file.read()

        except UnicodeDecodeError:

            with open(file_path, "r", encoding="latin-1") as file:

                log_content = file.read()

        except OSError:

            continue



        features = []



        for line in log_content.splitlines():

            parts = line.strip().split(" ", 3)



            if len(parts) < 4:

                continue



            level = parts[2].upper()

            message = parts[3]



            if level in ["WARNING", "ERROR"]:

                suspicious_activities += 1



            if " - " in message:

                message = message.rsplit(" - ", 1)[0]



            level_score = {

                "INFO": 0,

                "WARNING": 1,

                "ERROR": 2

            }.get(level, 1)

            keyword_score = sum(

                word in message.lower()

                for word in suspicious_words

            )

            features.append([

                level_score,

                len(message),

                keyword_score

            ])



        if len(features) >= 2:

            predictions = IsolationForest(

                contamination="auto",

                random_state=42

            ).fit_predict(features)

            ai_anomalies += int((predictions == -1).sum())



    activity_icons = {

        "Upload Evidence": "fa-upload",

        "Login": "fa-right-to-bracket",

        "Logout": "fa-right-from-bracket"

    }

    recent_activity = [

        {

            "action": activity["action"],

            "details": activity["details"],

            "timestamp": activity["timestamp"],

            "icon": activity_icons.get(

                activity["action"],

                "fa-clock-rotate-left"

            )

        }

        for activity in recent_activity

    ]



    return render_template(

        "dashboard.html",

        total_investigations=total_investigations,

        active_investigations=active_investigations,

        total_evidence=total_evidence,

        uploaded_evidence=uploaded_evidence,

        suspicious_activities=suspicious_activities,

        ai_anomalies=ai_anomalies,

        high_risk_anomalies=ai_anomalies,

        recent_investigations=recent_investigations,

        recent_activity=recent_activity

    )





@app.route("/investigations")

def investigations():



    conn = get_db_connection()



    investigation_list = conn.execute("""

        SELECT

            investigations.id,

            investigations.case_id,

            investigations.case_name,

            investigations.description,

            investigations.status,

            investigations.created_date,

            users.name AS investigator

        FROM investigations

        LEFT JOIN users

        ON investigations.created_by = users.id

        ORDER BY investigations.id DESC

    """).fetchall()



    conn.close()



    return render_template(

        "investigations.html",
        investigation_list=investigation_list,
        error=request.args.get("error")

    )



@app.route("/investigations/add", methods=["POST"])

def add_investigation():



    case_name = request.form.get("case_name", "").strip()

    description = request.form.get("description", "").strip()

    status = request.form.get("status", "Investigating")



    if not case_name:

        return redirect(url_for("investigations"))



    conn = get_db_connection()



    # Generate next case number

    latest_case = conn.execute("""

        SELECT case_id

        FROM investigations

        ORDER BY id DESC

        LIMIT 1

    """).fetchone()



    if latest_case:

        try:

            last_number = int(

                latest_case["case_id"].split("-")[-1]

            )

            next_number = last_number + 1

        except:

            next_number = 1

    else:

        next_number = 1



    case_id = f"INV-2026-{next_number:03d}"



    created_date = datetime.now().strftime(

        "%Y-%m-%d %H:%M:%S"

    )



    conn.execute("""

        INSERT INTO investigations

        (

            case_id,

            case_name,

            description,

            status,

            created_by,

            created_date

        )

        VALUES (?, ?, ?, ?, ?, ?)

    """, (

        case_id,

        case_name,

        description,

        status,

        session.get("user_id"),

        created_date

    ))



    conn.commit()

    conn.close()



    return redirect(url_for("investigations"))


@app.route("/investigations/<int:investigation_id>/edit", methods=["POST"])
def edit_investigation(investigation_id):

    case_id = request.form.get("case_id", "").strip()
    case_name = request.form.get("case_name", "").strip()
    description = request.form.get("description", "").strip()

    if not case_id or not case_name:
        return redirect(url_for(
            "investigations",
            error="Case ID and case name are required."
        ))

    conn = get_db_connection()
    investigation = conn.execute(
        "SELECT case_id FROM investigations WHERE id = ?",
        (investigation_id,)
    ).fetchone()

    if investigation is None:
        conn.close()
        abort(404)

    duplicate_case = conn.execute(
        "SELECT 1 FROM investigations WHERE case_id = ? AND id != ?",
        (case_id, investigation_id)
    ).fetchone()

    if duplicate_case:
        conn.close()
        return redirect(url_for(
            "investigations",
            error=f"Case ID {case_id} is already in use."
        ))

    conn.execute(
        """
        UPDATE investigations
        SET case_id = ?, case_name = ?, description = ?
        WHERE id = ?
        """,
        (case_id, case_name, description, investigation_id)
    )
    conn.commit()
    conn.close()

    log_action(
        "Edit Investigation",
        f"Updated case {investigation['case_id']} to {case_id}"
    )

    return redirect(url_for("investigations"))


@app.route("/investigations/<int:investigation_id>/status", methods=["POST"])
def update_investigation_status(investigation_id):

    allowed_statuses = {"Investigating", "Analysis", "Completed", "Archived"}
    status = request.form.get("status", "")

    if status not in allowed_statuses:
        abort(400, description="Invalid investigation status.")

    conn = get_db_connection()
    investigation = conn.execute(
        "SELECT case_id, status FROM investigations WHERE id = ?",
        (investigation_id,)
    ).fetchone()

    if investigation is None:
        conn.close()
        abort(404)

    conn.execute(
        "UPDATE investigations SET status = ? WHERE id = ?",
        (status, investigation_id)
    )
    conn.commit()
    conn.close()

    log_action(
        "Change Investigation Status",
        f"Changed {investigation['case_id']} status from "
        f"{investigation['status']} to {status}"
    )

    return redirect(url_for("investigations"))


@app.route("/investigations/<int:investigation_id>/delete", methods=["POST"])
def delete_investigation(investigation_id):

    if session.get("role") != "Admin":
        abort(403)

    conn = get_db_connection()
    investigation = conn.execute(
        "SELECT case_id FROM investigations WHERE id = ?",
        (investigation_id,)
    ).fetchone()

    if investigation is None:
        conn.close()
        abort(404)

    linked_evidence = conn.execute(
        "SELECT filename FROM evidence WHERE investigation_id = ?",
        (investigation_id,)
    ).fetchall()

    conn.execute(
        "DELETE FROM evidence WHERE investigation_id = ?",
        (investigation_id,)
    )
    conn.execute(
        "DELETE FROM investigations WHERE id = ?",
        (investigation_id,)
    )

    evidence_files = []
    for filename in {row["filename"] for row in linked_evidence}:
        remaining_records = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE filename = ?",
            (filename,)
        ).fetchone()[0]
        evidence_files.append((filename, remaining_records))

    conn.commit()
    conn.close()

    log_action(
        "Delete Investigation",
        f"Deleted case {investigation['case_id']} and its linked evidence records"
    )

    upload_root = os.path.realpath(UPLOAD_FOLDER)
    for filename, remaining_records in evidence_files:
        if remaining_records != 0 or os.path.basename(filename) != filename:
            continue

        file_path = os.path.realpath(os.path.join(upload_root, filename))
        if os.path.commonpath([upload_root, file_path]) == upload_root:
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except OSError as error:
                print("Evidence file cleanup error:", error)

    return redirect(url_for("investigations"))



@app.route("/evidence")

def evidence():



    conn = get_db_connection()



    evidence_query = """

        SELECT

            evidence.id,

            evidence.filename,

            evidence.file_type,

            evidence.upload_date,

            evidence.status,

            evidence.investigation_id,

            evidence.file_hash,

            users.name AS uploader,

            investigations.case_id,

            investigations.case_name

        FROM evidence

        LEFT JOIN users

        ON evidence.uploaded_by = users.id

        LEFT JOIN investigations

        ON evidence.investigation_id = investigations.id

    """

    investigation_id = request.args.get("investigation_id", type=int)



    if investigation_id is not None:

        evidence_query += " WHERE evidence.investigation_id = ?"

        evidence_parameters = (investigation_id,)

    else:

        evidence_parameters = ()



    evidence_query += " ORDER BY evidence.id DESC"

    evidence_list = conn.execute(

        evidence_query,

        evidence_parameters

    ).fetchall()

    evidence_summary = {

        "total": len(evidence_list),

        "linked": sum(

            evidence["investigation_id"] is not None

            for evidence in evidence_list

        ),

        "hashed": sum(

            bool(evidence["file_hash"])

            for evidence in evidence_list

        )

    }



    selected_investigation = None

    if investigation_id is not None:

        selected_investigation = conn.execute(

            "SELECT id, case_id, case_name FROM investigations WHERE id = ?",

            (investigation_id,)

        ).fetchone()



    conn.close()



    return render_template(

        "evidence.html",

        evidence_list=evidence_list,

        evidence_summary=evidence_summary,

        selected_investigation=selected_investigation,

        integrity=request.args.get("integrity"),

        integrity_file=request.args.get("file"),

        deleted=request.args.get("deleted")

    )



@app.route("/verify-integrity/<int:evidence_id>")



def verify_integrity(evidence_id):



    conn = get_db_connection()



    evidence = conn.execute("""

        SELECT *

        FROM evidence

        WHERE id = ?

    """, (evidence_id,)).fetchone()



    conn.close()



    if not evidence:

        return redirect(url_for("evidence"))



    filename = evidence["filename"]



    file_path = os.path.join(

        UPLOAD_FOLDER,

        filename

    )



    # Check whether physical file still exists

    if not os.path.exists(file_path):



        return redirect(

            url_for(

                "evidence",
                investigation_id=evidence["investigation_id"],
                integrity="missing",
                file=filename
            )

        )



    # Calculate current SHA-256

    sha256_hash = hashlib.sha256()



    with open(file_path, "rb") as saved_file:



        for chunk in iter(

            lambda: saved_file.read(4096),

            b""

        ):

            sha256_hash.update(chunk)



    current_hash = sha256_hash.hexdigest()



    original_hash = evidence["file_hash"]



    # Compare original and current hash

    if original_hash == current_hash:



        result = "verified"



    else:



        result = "modified"



    return redirect(

        url_for(

            "evidence",
            investigation_id=evidence["investigation_id"],
            integrity=result,
            file=filename
        )

    )





@app.route("/evidence/<int:evidence_id>/delete", methods=["POST"])

def delete_evidence(evidence_id):



    if session.get("role") != "Admin":

        abort(403)



    investigation_id = request.form.get("investigation_id", type=int)

    conn = get_db_connection()

    evidence = conn.execute(

        "SELECT filename, investigation_id FROM evidence WHERE id = ?",

        (evidence_id,)

    ).fetchone()



    if evidence is None:

        conn.close()

        abort(404)



    filename = evidence["filename"]

    linked_records = conn.execute(

        "SELECT COUNT(*) FROM evidence WHERE filename = ? AND id != ?",

        (filename, evidence_id)

    ).fetchone()[0]

    conn.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))

    conn.commit()

    conn.close()



    if linked_records == 0 and os.path.basename(filename) == filename:

        upload_root = os.path.realpath(UPLOAD_FOLDER)

        file_path = os.path.realpath(os.path.join(upload_root, filename))



        if os.path.commonpath([upload_root, file_path]) == upload_root:

            try:

                if os.path.isfile(file_path):

                    os.remove(file_path)

            except OSError as error:

                print("Evidence file cleanup error:", error)



    log_action("Delete Evidence", f"Deleted evidence file: {filename}")



    return redirect(

        url_for(

            "evidence",

            investigation_id=investigation_id or evidence["investigation_id"],

            deleted=filename

        )

    )



@app.route("/log-analysis")

def log_analysis():



    # Get the exact evidence filename from the URL

    filename = get_analysis_filename()



    log_content = ""

    events = []



    # Only analyze the selected file

    if filename:



        file_path = os.path.join(

            UPLOAD_FOLDER,

            filename

        )



        if os.path.exists(file_path):



            try:



                with open(

                    file_path,

                    "r",

                    encoding="utf-8"

                ) as file:



                    log_content = file.read()



            except UnicodeDecodeError:



                with open(

                    file_path,

                    "r",

                    encoding="latin-1"

                ) as file:



                    log_content = file.read()



            # =========================

            # ANALYZE LOG EVENTS

            # =========================



            for line in log_content.splitlines():



                line = line.strip()



                if not line:

                    continue



                parts = line.split(" ", 3)



                if len(parts) >= 4:



                    date = parts[0]

                    time = parts[1]

                    level = parts[2]

                    message = parts[3]



                    # Determine severity

                    if level.upper() == "WARNING":



                        severity = "High"



                    elif level.upper() == "ERROR":



                        severity = "Critical"



                    elif level.upper() == "INFO":



                        severity = "Low"



                    else:



                        severity = "Medium"



                    # Detect username

                    username = "-"



                    if " - " in message:



                        message_parts = message.rsplit(

                            " - ",

                            1

                        )



                        if len(message_parts) == 2:



                            message = message_parts[0]

                            username = message_parts[1]



                    events.append({



                        "date": date,

                        "time": time,

                        "level": level,

                        "message": message,

                        "username": username,

                        "severity": severity



                    })





    # =========================

    # STATISTICS

    # =========================



    total_events = len(events)



    suspicious_events = 0

    high_risk_events = 0

    normal_events = 0



    for event in events:



        if event["level"].upper() in [

            "WARNING",

            "ERROR"

        ]:



            suspicious_events += 1



        if event["severity"] in [

            "High",

            "Critical"

        ]:



            high_risk_events += 1



        if event["severity"] == "Low":



            normal_events += 1





    return render_template(

        "log_analysis.html",

        filename=filename,

        log_content=log_content,

        events=events,

        total_events=total_events,

        suspicious_events=suspicious_events,

        high_risk_events=high_risk_events,

        normal_events=normal_events

    )



@app.route("/timeline")

def timeline():



    filename = get_analysis_filename()



    log_content = ""

    events = []



    if filename:



        file_path = os.path.join(UPLOAD_FOLDER, filename)



        if os.path.exists(file_path):



            try:

                with open(file_path, "r", encoding="utf-8") as file:

                    log_content = file.read()



            except UnicodeDecodeError:



                with open(file_path, "r", encoding="latin-1") as file:

                    log_content = file.read()



            for line in log_content.splitlines():



                line = line.strip()



                if not line:

                    continue



                parts = line.split(" ", 3)



                if len(parts) >= 4:



                    date = parts[0]

                    time = parts[1]

                    level = parts[2]

                    message = parts[3]



                    if level.upper() == "WARNING":

                        severity = "High"



                    elif level.upper() == "ERROR":

                        severity = "Critical"



                    elif level.upper() == "INFO":

                        severity = "Low"



                    else:

                        severity = "Medium"



                    username = "-"



                    if " - " in message:



                        message_parts = message.rsplit(" - ", 1)



                        if len(message_parts) == 2:



                            message = message_parts[0]

                            username = message_parts[1]



                    events.append({

                        "date": date,

                        "time": time,

                        "level": level,

                        "message": message,

                        "username": username,

                        "severity": severity

                    })





    # Sort events by date and time



    events.sort(

        key=lambda event: (

            event["date"],

            event["time"]

        )

    )





    total_events = len(events)



    suspicious_events = 0

    high_risk_events = 0

    normal_events = 0





    for event in events:



        if event["level"].upper() in ["WARNING", "ERROR"]:

            suspicious_events += 1



        if event["severity"] in ["High", "Critical"]:

            high_risk_events += 1



        if event["severity"] == "Low":

            normal_events += 1





    return render_template(

        "timeline.html",

        filename=filename,

        log_content=log_content,

        events=events,

        total_events=total_events,

        suspicious_events=suspicious_events,

        high_risk_events=high_risk_events,

        normal_events=normal_events

    )



@app.route("/upload", methods=["GET", "POST"])

def upload():



    error = None

    success = None

    investigation_id = request.values.get("investigation_id", type=int)

    selected_investigation = None



    if investigation_id is not None:

        conn = get_db_connection()

        selected_investigation = conn.execute(

            "SELECT id, case_id, case_name FROM investigations WHERE id = ?",

            (investigation_id,)

        ).fetchone()

        conn.close()



        if selected_investigation is None:

            abort(404)



    if request.method == "POST":



        file = request.files.get("evidence")



        if not file or not file.filename:



            error = "Please select a file."



        else:



            filename = secure_filename(file.filename)



            if not filename:



                error = "Invalid filename."



            else:



                # Save physical file

                file_path = os.path.join(

                    UPLOAD_FOLDER,

                    filename

                )



                file.save(file_path)



# Calculate SHA-256 hash of the evidence file

                sha256_hash = hashlib.sha256()



                with open(file_path, "rb") as saved_file:



                    for chunk in iter(lambda: saved_file.read(4096), b""):

                        sha256_hash.update(chunk)



                file_hash = sha256_hash.hexdigest()



                # Get file type

                file_type = os.path.splitext(

                    filename

                )[1].replace(".", "").upper()



                if not file_type:

                    file_type = "UNKNOWN"



                # Get current date and time

                upload_date = datetime.now().strftime(

                    "%Y-%m-%d %H:%M:%S"

                )



                # Save evidence information into database

                conn = get_db_connection()



                existing_evidence = conn.execute(

                    """

                    SELECT * FROM evidence

                    WHERE filename = ?

                    """,

                    (filename,)

                ).fetchone()



                if existing_evidence:



                    conn.execute(

                        """

                        UPDATE evidence

                        SET uploaded_by = ?,

                            upload_date = ?,

                            status = ?,

                            file_hash = ?,

                            investigation_id = COALESCE(?, investigation_id)

                        WHERE filename = ?

                        """,

                        (

                            session.get("user_id"),

                            upload_date,

                            "Uploaded",

                            file_hash,

                            investigation_id,

                            filename

                        )

                    )



                else:



                    conn.execute(

                        """

                        INSERT INTO evidence

                        (

                            filename,

                            file_type,

                            uploaded_by,

                            upload_date,

                            status,

                            file_hash,

                            investigation_id

                        )

                        VALUES (?, ?, ?, ?, ?, ?, ?)

                        """,

                        (

                            filename,

                            file_type,

                            session.get("user_id"),

                            upload_date,

                            "Uploaded",

                            file_hash,

                            investigation_id

                        )

                    )



                conn.commit()

                conn.close()



                log_action(

                    "Upload Evidence",

                    f"Uploaded evidence file: {filename}"

                )



                success = (

                    f"Evidence '{filename}' uploaded successfully."

                )



    uploaded_files = sorted(
        (
            filename
            for filename in os.listdir(UPLOAD_FOLDER)
            if os.path.isfile(os.path.join(UPLOAD_FOLDER, filename))
        ),
        key=lambda filename: os.path.getmtime(
            os.path.join(UPLOAD_FOLDER, filename)
        ),
        reverse=True
    )[:1]



    return render_template(

        "upload.html",

        uploaded_files=uploaded_files,

        error=error,

        success=success,

        selected_investigation=selected_investigation

    )



def analyze_log_file(filename):

    log_content = ""
    events = []

    # ============================================================
    # 1. READ SELECTED EVIDENCE
    # ============================================================

    if filename:

        file_path = os.path.join(
            UPLOAD_FOLDER,
            filename
        )

        if os.path.exists(file_path):

            try:
                with open(
                    file_path,
                    "r",
                    encoding="utf-8"
                ) as file:
                    log_content = file.read()

            except UnicodeDecodeError:

                with open(
                    file_path,
                    "r",
                    encoding="latin-1"
                ) as file:
                    log_content = file.read()

            # ====================================================
            # 2. PARSE LOG
            # ====================================================

            for line in log_content.splitlines():

                line = line.strip()

                if not line:
                    continue

                parts = line.split(" ", 3)

                if len(parts) < 4:
                    continue

                date = parts[0]
                time = parts[1]
                level = parts[2]
                message = parts[3]

                username = "-"

                if " - " in message:

                    message_parts = message.rsplit(
                        " - ",
                        1
                    )

                    message = message_parts[0]
                    username = message_parts[1]

                try:

                    event_datetime = datetime.strptime(
                        f"{date} {time}",
                        "%Y-%m-%d %H:%M:%S"
                    )

                except ValueError:

                    continue

                message_lower = message.lower()
                level_upper = level.upper()

                # ====================================================
                # 3. EXPLICIT SECURITY EVENT DETECTION
                # ====================================================

                security_reasons = []

                # Suspicious / malicious security descriptions
                if re.search(
                    r"\b(suspicious|unauthorized|malicious|intrusion|"
                    r"breach|compromise|attack)\b",
                    message_lower
                ):

                    security_reasons.append(
                        "Explicit security-related event"
                    )

                # Login failures
                if re.search(
                    r"\b(failed|failure|invalid|denied|rejected)\b",
                    message_lower
                ) and re.search(
                    r"\b(login|logon|signin|sign-in|authentication|auth)\b",
                    message_lower
                ):

                    security_reasons.append(
                        "Login failure recorded"
                    )

                # Multiple/repeated login failures
                if re.search(
                    r"\b(multiple|repeated|several|many)\b",
                    message_lower
                ) and re.search(
                    r"\b(failed|failure|invalid|denied|rejected)\b",
                    message_lower
                ) and re.search(
                    r"\b(login|logon|signin|sign-in|authentication|auth)\b",
                    message_lower
                ):

                    security_reasons.append(
                        "Multiple login failures recorded"
                    )

                explicit_security_event = (
                    len(security_reasons) > 0
                )

                # ====================================================
                # 4. BASIC NUMERICAL FEATURES
                # ====================================================

                level_score = {
                    "INFO": 0,
                    "WARNING": 1,
                    "ERROR": 2
                }.get(level_upper, 1)

                events.append({

                    "date": date,
                    "time": time,
                    "level": level,
                    "message": message,
                    "username": username,

                    "datetime_obj": event_datetime,

                    "level_score": level_score,

                    "message_length": len(message),

                    "explicit_security_event":
                        explicit_security_event,

                    "security_reasons":
                        security_reasons,

                    "ai_result": "Normal",
                    "ai_risk": "Low",
                    "ai_score": 0,
                    "ai_reason": ""

                })

    # ============================================================
    # 5. BEHAVIOURAL AI
    # ============================================================

    if len(events) >= 2:

        events.sort(
            key=lambda event: event["datetime_obj"]
        )

        # Group events by user
        user_events = {}

        for event in events:

            user = event["username"]

            if user not in user_events:
                user_events[user] = []

            user_events[user].append(event)

        # --------------------------------------------------------
        # Calculate behavioural activity
        # --------------------------------------------------------

        for event in events:

            user = event["username"]

            current_time = event["datetime_obj"]

            previous_events = user_events[user]

            events_10min = 0

            for previous in previous_events:

                difference = (
                    current_time -
                    previous["datetime_obj"]
                ).total_seconds()

                if 0 <= difference <= 600:
                    events_10min += 1

            event["events_10min"] = events_10min

        # --------------------------------------------------------
        # Isolation Forest
        # --------------------------------------------------------

        features = []

        for event in events:

            features.append([

                event["level_score"],

                event["message_length"],

                event["events_10min"]

            ])

        if len(features) >= 2:

            model = IsolationForest(
                contamination="auto",
                random_state=42,
                n_estimators=200
            )

            predictions = model.fit_predict(
                features
            )

            decision_scores = model.decision_function(
                features
            )

        else:

            predictions = [1] * len(events)
            decision_scores = [0] * len(events)

        # ========================================================
        # 6. FINAL DECISION
        # ========================================================

        for index, event in enumerate(events):

            # ----------------------------------------------------
            # FIRST PRIORITY:
            # Explicit security event
            # ----------------------------------------------------

            if event["explicit_security_event"]:

                event["ai_result"] = "Anomaly"

                event["ai_risk"] = "High"

                event["ai_score"] = 100

                event["ai_reason"] = ", ".join(
                    event["security_reasons"]
                )

                continue

            # ----------------------------------------------------
            # SECOND PRIORITY:
            # Isolation Forest
            # ----------------------------------------------------

            if predictions[index] == -1:

                event["ai_result"] = "Anomaly"

                event["ai_risk"] = "Medium"

                score = (
                    50 -
                    (float(decision_scores[index]) * 100)
                )

                event["ai_score"] = round(
                    max(0, min(100, score)),
                    1
                )

                event["ai_reason"] = (
                    "Isolation Forest detected "
                    "an unusual behavioural pattern"
                )

            else:

                event["ai_result"] = "Normal"

                event["ai_risk"] = "Low"

                event["ai_score"] = 0

                event["ai_reason"] = (
                    "No significant anomaly detected"
                )

    else:

        for event in events:

            event["ai_result"] = "Insufficient Data"

            event["ai_risk"] = "Unknown"

            event["ai_score"] = 0

            event["ai_reason"] = (
                "Not enough events for analysis"
            )

    # ============================================================
    # 7. STATISTICS
    # ============================================================

    total_events = len(events)

    anomalies = sum(
        1
        for event in events
        if event["ai_result"] == "Anomaly"
    )

    normal_events = sum(
        1
        for event in events
        if event["ai_result"] == "Normal"
    )

    return events, total_events, anomalies, normal_events


@app.route("/ai-detection")
def ai_detection():

    filename = get_analysis_filename()
    events, total_events, anomalies, normal_events = analyze_log_file(filename)

    return render_template(

        "ai_detection.html",

        filename=filename,

        events=events,

        total_events=total_events,

        anomalies=anomalies,

        normal_events=normal_events

    )


@app.route("/analytics")

def analytics():



    filename = get_analysis_filename()


    events, total_events, anomalies, normal_events = analyze_log_file(filename)
    suspicious_events = sum(
        1
        for event in events
        if event["level"].upper() in {"WARNING", "ERROR"}
    )



    return render_template(

        "analytics.html",

        filename=filename,

        total_events=total_events,

        normal_events=normal_events,

        suspicious_events=suspicious_events,

        anomalies=anomalies

    )



@app.route("/reports")

def reports():



    filename = get_analysis_filename()

    print_view = request.args.get("print") == "1"



    events = []



    total_events = 0

    normal_events = 0

    suspicious_events = 0

    high_risk_events = 0



    if filename:



        file_path = os.path.join(

            UPLOAD_FOLDER,

            filename

        )



        if os.path.exists(file_path):



            try:



                with open(

                    file_path,

                    "r",

                    encoding="utf-8"

                ) as file:



                    log_content = file.read()



            except UnicodeDecodeError:



                with open(

                    file_path,

                    "r",

                    encoding="latin-1"

                ) as file:



                    log_content = file.read()





            for line in log_content.splitlines():



                line = line.strip()



                if not line:

                    continue





                parts = line.split(" ", 3)





                if len(parts) >= 4:



                    date = parts[0]

                    time = parts[1]

                    level = parts[2]

                    message = parts[3]





                    if level.upper() == "WARNING":



                        severity = "High"



                    elif level.upper() == "ERROR":



                        severity = "Critical"



                    elif level.upper() == "INFO":



                        severity = "Low"



                    else:



                        severity = "Medium"





                    username = "-"



                    if " - " in message:



                        message_parts = message.rsplit(

                            " - ",

                            1

                        )



                        if len(message_parts) == 2:



                            message = message_parts[0]

                            username = message_parts[1]





                    events.append({



                        "date": date,

                        "time": time,

                        "level": level,

                        "message": message,

                        "username": username,

                        "severity": severity



                    })





    total_events = len(events)





    for event in events:



        if event["severity"] == "Low":



            normal_events += 1





        if event["level"].upper() in [

            "WARNING",

            "ERROR"

        ]:



            suspicious_events += 1





        if event["severity"] in [

            "High",

            "Critical"

        ]:



            high_risk_events += 1





    analyzed_events, total_events, anomalies, normal_events = analyze_log_file(
        filename
    )

    events = analyzed_events

    suspicious_events = sum(
        1
        for event in events
        if event["level"].upper() in {"WARNING", "ERROR"}
    )

    for event in events:

        event["severity"] = {
            "WARNING": "High",
            "ERROR": "Critical",
            "INFO": "Low",
        }.get(event["level"].upper(), "Medium")

    high_risk_events = sum(
        1
        for event in events
        if event["severity"] in {"High", "Critical"}
    )

    return render_template(



        "reports.html",



        filename=filename,

        events=events,



        total_events=total_events,

        normal_events=normal_events,

        suspicious_events=suspicious_events,

        high_risk_events=high_risk_events,

        anomalies=anomalies,

        print_view=print_view

    )



@app.route("/users")

def users():



    if session.get("role") != "Admin":



        abort(403)



    conn = get_db_connection()



    users = conn.execute(

        "SELECT * FROM users ORDER BY id"

    ).fetchall()



    conn.close()





    total_users = len(users)



    admin_count = 0

    investigator_count = 0





    for user in users:



        if user["role"] == "Admin":



            admin_count += 1



        elif user["role"] == "Investigator":



            investigator_count += 1





    return render_template(



        "users.html",



        users=users,



        total_users=total_users,



        admin_count=admin_count,



        investigator_count=investigator_count



    )





@app.route("/users/add", methods=["POST"])

def add_user():



    if session.get("role") != "Admin":

        abort(403)



    name = request.form.get("name", "").strip()

    username = request.form.get("username", "").strip()

    password = request.form.get("password", "")

    role = request.form.get("role", "").strip()



    # Validate fields

    if not name:

        return redirect(

            url_for("users", error="Name is required.")

        )



    if not username:

        return redirect(

            url_for("users", error="Username is required.")

        )



    if not password:

        return redirect(

            url_for("users", error="Password is required.")

        )



    if len(password) < 6:

        return redirect(

            url_for("users", error="Password must be at least 6 characters.")

        )



    if role not in ["Admin", "Investigator"]:

        return redirect(

            url_for("users", error="Invalid user role.")

        )



    conn = get_db_connection()



    # Check whether username already exists

    existing_user = conn.execute(

        """

        SELECT id

        FROM users

        WHERE username = ?

        """,

        (username,)

    ).fetchone()



    if existing_user:

        conn.close()



        return redirect(

            url_for(

                "users",

                error="That username is already in use."

            )

        )



    # Hash the password

    hashed_password = generate_password_hash(password)



    # Create user

    conn.execute(

        """

        INSERT INTO users

        (name, username, password, role)

        VALUES (?, ?, ?, ?)

        """,

        (

            name,

            username,

            hashed_password,

            role

        )

    )



    conn.commit()

    conn.close()



    return redirect(url_for("users"))





@app.route("/users/<int:user_id>/edit", methods=["POST"])

def edit_user(user_id):



    if session.get("role") != "Admin":



        abort(403)



    name = request.form.get("name", "").strip()

    username = request.form.get("username", "").strip()

    password = request.form.get("password", "")

    role = request.form.get("role", "").strip()



    if not name or not username or role not in ["Admin", "Investigator"]:



        return redirect(url_for("users", error="Complete all required user fields."))



    conn = get_db_connection()

    existing_user = conn.execute(

        "SELECT * FROM users WHERE id = ?",

        (user_id,)

    ).fetchone()



    if existing_user is None:



        conn.close()



        return redirect(url_for("users", error="User not found."))



    updated_password = (

        generate_password_hash(password)

        if password

        else existing_user["password"]

    )



    try:



        conn.execute(

            """

            UPDATE users

            SET name = ?, username = ?, password = ?, role = ?

            WHERE id = ?

            """,

            (name, username, updated_password, role, user_id)

        )

        conn.commit()



    except sqlite3.IntegrityError:



        conn.close()



        return redirect(url_for("users", error="That username is already in use."))



    conn.close()



    return redirect(url_for("users"))





@app.route("/users/<int:user_id>/delete", methods=["POST"])

def delete_user(user_id):



    if session.get("role") != "Admin":



        abort(403)



    if session.get("user_id") == user_id:



        return redirect(url_for("users", error="You cannot delete your own account."))



    conn = get_db_connection()

    conn.execute(

        "DELETE FROM users WHERE id = ?",

        (user_id,)

    )

    conn.commit()

    conn.close()



    return redirect(url_for("users"))







@app.route("/settings")

def settings():

    return render_template("settings.html")



@app.route("/settings/change-password", methods=["POST"])

def change_password():



    current_password = request.form.get("current_password", "")

    new_password = request.form.get("new_password", "")

    confirm_password = request.form.get("confirm_password", "")



    # Check all fields

    if not current_password or not new_password or not confirm_password:

        return render_template(

            "settings.html",

            password_error="Please complete all password fields."

        )



    # Check new password confirmation

    if new_password != confirm_password:

        return render_template(

            "settings.html",

            password_error="New password and confirmation do not match."

        )



    # Minimum password length

    if len(new_password) < 6:

        return render_template(

            "settings.html",

            password_error="New password must be at least 6 characters."

        )



    conn = get_db_connection()



    user = conn.execute(

        """

        SELECT *

        FROM users

        WHERE id = ?

        """,

        (session.get("user_id"),)

    ).fetchone()



    if not user:

        conn.close()



        return render_template(

            "settings.html",

            password_error="User account could not be found."

        )



    stored_password = user["password"]



    # Check the current password

    password_correct = False



    try:

        # For hashed passwords

        password_correct = check_password_hash(

            stored_password,

            current_password

        )



    except (ValueError, TypeError):

        # For old plain-text passwords

        password_correct = (

            stored_password == current_password

        )



    # If password is wrong

    if not password_correct:

        conn.close()



        return render_template(

            "settings.html",

            password_error="Current password is incorrect."

        )



    # Create a secure hash for the NEW password

    hashed_password = generate_password_hash(new_password)



    # Save the new password

    conn.execute(

        """

        UPDATE users

        SET password = ?

        WHERE id = ?

        """,

        (

            hashed_password,

            session.get("user_id")

        )

    )



    conn.commit()

    conn.close()



    return render_template(

        "settings.html",

        password_success="Password changed successfully."

    )







if __name__ == "__main__":



    init_database()



    app.run(debug=True)