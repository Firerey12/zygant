import os

import pandas as pd
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, send_file
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

from db.connection import get_db
from utils.scoring import score_dataframe

load_dotenv()

app = Flask(
    __name__,
    template_folder='./templates',
    static_folder='./templates/static'
)

app.config["UPLOAD_FOLDER"] = "uploads"
REPORT_FOLDER = "reports"

os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs("uploads", exist_ok=True)


# ------------------------
# HOME -> DASHBOARD
# ------------------------
@app.route("/")
def dashboard():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT v.id, c.cve_id, v.final_score, v.priority
                FROM vulnerabilities v
                JOIN cves c ON v.cve_id = c.cve_id
                ORDER BY v.final_score DESC NULLS LAST
            """)
            vulns = cur.fetchall()
    finally:
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

            conn = get_db()
            try:
                with conn.cursor() as cur:
                    for _, row in scored_df.iterrows():
                        cve_id = row.get("cve_id")
                        if not cve_id:
                            continue

                        cve_id = str(cve_id).upper()

                        # Upsert CVE enrichment data
                        cur.execute("""
                            INSERT INTO cves (
                                cve_id, description, cvss_base_score,
                                epss_score, epss_percentile, is_kev, enriched_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
                            ON CONFLICT (cve_id) DO UPDATE SET
                                description     = EXCLUDED.description,
                                cvss_base_score = EXCLUDED.cvss_base_score,
                                epss_score      = EXCLUDED.epss_score,
                                epss_percentile = EXCLUDED.epss_percentile,
                                is_kev          = EXCLUDED.is_kev,
                                enriched_at     = NOW(),
                                updated_at      = NOW()
                        """, (
                            cve_id,
                            row.get("description"),
                            row.get("cvss_base_score"),
                            row.get("epss_score"),
                            row.get("epss_percentile"),
                            bool(row.get("is_kev", False)),
                        ))

                        priority = str(row.get("priority", "low")).lower()

                        # Upsert vulnerability — no agent for CSV uploads;
                        # the partial unique index on (cve_id) WHERE agent_id IS NULL
                        # prevents duplicate rows for the same CVE.
                        cur.execute("""
                            INSERT INTO vulnerabilities (
                                cve_id, source,
                                tier1_ml_score, final_score, priority, scored_at
                            ) VALUES (%s, 'upload', %s, %s, %s::criticality_level, NOW())
                            ON CONFLICT (cve_id) WHERE agent_id IS NULL
                            DO UPDATE SET
                                tier1_ml_score = EXCLUDED.tier1_ml_score,
                                final_score    = EXCLUDED.final_score,
                                priority       = EXCLUDED.priority,
                                scored_at      = NOW(),
                                updated_at     = NOW()
                        """, (
                            cve_id,
                            row.get("lightgbm_predicted_score"),
                            row.get("final_score"),
                            priority,
                        ))

                conn.commit()
            finally:
                conn.close()

            return redirect(url_for("dashboard"))

    return render_template("upload.html")


# ------------------------
# VULNERABILITY DETAIL
# ------------------------
@app.route("/vuln/<int:vuln_id>", methods=["GET", "POST"])
def vuln_detail(vuln_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    v.id,
                    c.cve_id,
                    c.cvss_base_score,
                    c.description,
                    v.final_score,
                    v.priority,
                    v.status,
                    r.file_path  AS report_path
                FROM vulnerabilities v
                JOIN cves c ON v.cve_id = c.cve_id
                LEFT JOIN reports r ON r.vulnerability_id = v.id
                WHERE v.id = %s
            """, (vuln_id,))
            vuln = cur.fetchone()

        if not vuln:
            return "Vulnerability not found", 404

        if request.method == "POST" and not vuln["report_path"]:
            report_text = generate_report(vuln)
            filepath = generate_pdf(report_text, vuln)

            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO reports (vulnerability_id, file_path, generated_at)
                    VALUES (%s, %s, NOW())
                """, (vuln_id, filepath))
            conn.commit()

            return redirect(url_for("vuln_detail", vuln_id=vuln_id))

    finally:
        conn.close()

    return render_template(
        "vuln_detail.html",
        vuln=vuln,
        report_exists=bool(vuln["report_path"])
    )


# ------------------------
# DOWNLOAD REPORT
# ------------------------
@app.route("/download/<int:vuln_id>")
def download_report(vuln_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT r.file_path, c.cve_id
                FROM reports r
                JOIN vulnerabilities v ON r.vulnerability_id = v.id
                JOIN cves c ON v.cve_id = c.cve_id
                WHERE v.id = %s
            """, (vuln_id,))
            result = cur.fetchone()
    finally:
        conn.close()

    if not result or not result["file_path"]:
        return "Report not found", 404

    return send_file(
        result["file_path"],
        as_attachment=True,
        download_name=f"{result['cve_id']}.pdf",
        mimetype="application/pdf"
    )


# ------------------------
# OLLAMA LLM CALL
# ------------------------
def generate_report(vuln):
    prompt = f"""
    Generate a concise vulnerability report.

    CVE: {vuln['cve_id']}
    CVSS Score: {vuln['cvss_base_score']}
    Priority: {vuln['priority']}
    Description: {vuln['description']}

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
    filename = f"{vuln['cve_id']}.pdf"
    filepath = os.path.join(REPORT_FOLDER, filename)

    doc = SimpleDocTemplate(filepath)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph(f"CVE: {vuln['cve_id']}", styles["Title"]))
    content.append(Spacer(1, 12))
    content.append(Paragraph(f"CVSS Score: {vuln['cvss_base_score']}", styles["Normal"]))
    content.append(Paragraph(f"Priority: {vuln['priority']}", styles["Normal"]))
    content.append(Spacer(1, 12))

    for line in report_text.split("\n"):
        content.append(Paragraph(line, styles["Normal"]))
        content.append(Spacer(1, 8))

    doc.build(content)
    return filepath


if __name__ == "__main__":
    app.run(debug=True)
