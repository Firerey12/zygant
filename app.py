import os
import sqlite3
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
import requests
from flask import Flask, render_template, request, redirect, url_for
from flask import send_file

from utils.scoring import score_dataframe

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
DB_PATH = "db/database.db"
REPORT_FOLDER = "reports"

os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs("uploads", exist_ok=True)
os.makedirs("db", exist_ok=True)


# ------------------------
# DB INIT
# ------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            published TEXT,
            cvss_base_score REAL,
            description TEXT,
            is_kev INTEGER,
            epss_percentile REAL,
            predicted_score REAL,
            final_score REAL,
            priority TEXT,
            report_path TEXT
        )
    """)


    conn.commit()
    conn.close()


init_db()


# ------------------------
# HOME -> DASHBOARD
# ------------------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT id, cve_id, final_score, priority
        FROM vulnerabilities
        ORDER BY final_score DESC
    """)

    vulns = c.fetchall()
    conn.close()

    return render_template("dashboard.html", vulns=vulns)


# ------------------------
# UPLOAD PAGE
# ------------------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files["file"]

        if file:
            path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(path)

            df = pd.read_csv(path)
            scored_df = score_dataframe(df)

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()

            for _, row in scored_df.iterrows():
                c.execute("""
                    INSERT INTO vulnerabilities (
                        cve_id,
                        published,
                        cvss_base_score,
                        description,
                        is_kev,
                        epss_percentile,
                        predicted_score,
                        final_score,
                        priority
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get("cve_id"),
                    row.get("published"),
                    row.get("cvss_base_score"),
                    row.get("description"),
                    int(row.get("is_kev", 0)),
                    row.get("epss_percentile"),
                    row.get("lightgbm_predicted_score"),
                    row.get("final_score"),
                    row.get("priority")
                ))

            conn.commit()
            conn.close()

            return redirect(url_for("dashboard"))

    return render_template("upload.html")


# ------------------------
# VULNERABILITY DETAIL
# ------------------------
@app.route("/vuln/<int:vuln_id>", methods=["GET", "POST"])
def vuln_detail(vuln_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    vuln = c.fetchone()

    report_path = vuln[10]  # new column

    # If generating report
    if request.method == "POST" and not report_path:
        report_text = generate_report(vuln)
        filepath = generate_pdf(report_text, vuln)

        c.execute(
            "UPDATE vulnerabilities SET report_path = ? WHERE id = ?",
            (filepath, vuln_id)
        )
        conn.commit()

        conn.close()
        return redirect(url_for("vuln_detail", vuln_id=vuln_id))

    conn.close()

    return render_template(
        "vuln_detail.html",
        vuln=vuln,
        report_exists=bool(report_path)
    )

@app.route("/download/<int:vuln_id>")
def download_report(vuln_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT report_path, cve_id FROM vulnerabilities WHERE id = ?", (vuln_id,))
    result = c.fetchone()
    conn.close()

    if not result or not result[0]:
        return "Report not found", 404

    return send_file(
        result[0],
        as_attachment=True,
        download_name=f"{result[1]}.pdf",
        mimetype="application/pdf"
    )
# ------------------------
# OLLAMA LLM CALL
# ------------------------
def generate_report(vuln):
    prompt = f"""
    Generate a concise vulnerability report.

    CVE: {vuln[1]}
    CVSS Score: {vuln[3]}
    Priority: {vuln[8]}
    Description: {vuln[4]}

    Include:
    - What the vulnerability is
    - Impact
    - Remediation steps
    """

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        }
    )

    return response.json().get("response", "Error generating report")

def generate_pdf(report_text, vuln):
    filename = f"{vuln[1]}.pdf"
    filepath = os.path.join(REPORT_FOLDER, filename)

    doc = SimpleDocTemplate(filepath)
    styles = getSampleStyleSheet()

    content = []

    content.append(Paragraph(f"CVE: {vuln[1]}", styles["Title"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph(f"CVSS Score: {vuln[3]}", styles["Normal"]))
    content.append(Paragraph(f"Priority: {vuln[8]}", styles["Normal"]))
    content.append(Spacer(1, 12))

    for line in report_text.split("\n"):
        content.append(Paragraph(line, styles["Normal"]))
        content.append(Spacer(1, 8))

    doc.build(content)

    return filepath

if __name__ == "__main__":
    app.run(debug=True)