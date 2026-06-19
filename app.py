from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL

app = Flask(
    __name__,
    template_folder='./templates',
    static_folder='./templates/static'
)

app.secret_key = 'zygant_secret_key_2025'
app.config['MYSQL_HOST']     = 'localhost'
app.config['MYSQL_USER']     = 'root'
app.config['MYSQL_PASSWORD'] = 'yourpassword'   # <-- change this
app.config['MYSQL_DB']       = 'zygant'

mysql = MySQL(app)

# ── login required ────────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── AUTH ──────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email')
        password = request.form.get('password')
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, name, email, role FROM users WHERE email = %s AND status = 'Active'", (email,))
            user = cur.fetchone()
            cur.close()
            if user:
                session['user_id']    = user[0]
                session['user_name']  = user[1]
                session['user_email'] = user[2]
                session['user_role']  = user[3]
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password.', 'error')
        except Exception as e:
            flash('Database error. Please try again.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── PAGE ROUTES ───────────────────────────────────────────────
@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/assets')
@login_required
def assets():
    return render_template('asset_inventory.html')

@app.route('/scan')
@login_required
def scan():
    return render_template('scan_trigger.html')

@app.route('/cve')
@login_required
def cve():
    return render_template('index.html')

@app.route('/users')
@login_required
def users():
    return render_template('user_management.html')

@app.route('/audit')
@login_required
def audit():
    return render_template('audit_log.html')

@app.route('/prioritization')
@login_required
def prioritization():
    return render_template('prioritization.html')

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    if request.method == 'POST':
        issue_type   = request.form.get('issue_type')
        subject      = request.form.get('subject')
        description  = request.form.get('description')
        priority     = request.form.get('priority')
        submitted_by = session.get('user_email', 'unknown')
        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO support_tickets (issue_type, subject, description, priority, submitted_by, status)
                VALUES (%s, %s, %s, %s, %s, 'Open')
            """, (issue_type, subject, description, priority, submitted_by))
            mysql.connection.commit()
            cur.close()
            flash('Ticket submitted successfully.', 'success')
        except Exception as e:
            flash('Error submitting ticket.', 'error')
        return redirect(url_for('support'))
    return render_template('support.html')

# ── API: ASSETS ───────────────────────────────────────────────
@app.route('/api/assets')
@login_required
def api_assets():
    risk = request.args.get('risk')
    asset_type = request.args.get('type')
    try:
        cur = mysql.connection.cursor()
        query = "SELECT id, hostname, ip_address, os, asset_type, owner, risk_level, last_scanned FROM assets WHERE 1=1"
        params = []
        if risk:
            query += " AND risk_level = %s"
            params.append(risk)
        if asset_type:
            query += " AND asset_type = %s"
            params.append(asset_type)
        query += " ORDER BY FIELD(risk_level, 'Critical','High','Medium','Low')"
        cur.execute(query, params)
        rows = cur.fetchall()
        cur.close()
        keys = ['id','hostname','ip_address','os','asset_type','owner','risk_level','last_scanned']
        result = []
        for row in rows:
            d = dict(zip(keys, row))
            if d['last_scanned']:
                d['last_scanned'] = str(d['last_scanned'])
            result.append(d)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: VULNERABILITIES ──────────────────────────────────────
@app.route('/api/vulnerabilities')
@login_required
def api_vulnerabilities():
    severity = request.args.get('severity')
    status   = request.args.get('status')
    sort_by  = request.args.get('sort', 'cvss_score')
    allowed_sorts = ['cvss_score', 'zygant_score', 'severity']
    if sort_by not in allowed_sorts:
        sort_by = 'cvss_score'
    try:
        cur = mysql.connection.cursor()
        query = """
            SELECT v.id, v.cve_id, v.severity, v.cvss_score, v.zygant_score,
                   v.epss_score, v.kev_listed, v.description, v.status,
                   v.detected_on, a.hostname
            FROM vulnerabilities v
            LEFT JOIN assets a ON v.asset_id = a.id
            WHERE 1=1
        """
        params = []
        if severity:
            query += " AND v.severity = %s"
            params.append(severity)
        if status:
            query += " AND v.status = %s"
            params.append(status)
        query += f" ORDER BY v.{sort_by} DESC"
        cur.execute(query, params)
        rows = cur.fetchall()
        cur.close()
        keys = ['id','cve_id','severity','cvss_score','zygant_score','epss_score','kev_listed','description','status','detected_on','hostname']
        result = []
        for row in rows:
            d = dict(zip(keys, row))
            if d['detected_on']:
                d['detected_on'] = str(d['detected_on'])
            d['kev_listed'] = bool(d['kev_listed'])
            result.append(d)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: STATS ────────────────────────────────────────────────
@app.route('/api/stats')
@login_required
def api_stats():
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY severity
        """)
        rows = cur.fetchall()
        cur.close()
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        for row in rows:
            sev = row[0].lower()
            if sev in stats:
                stats[sev] = row[1]
            stats['total'] += row[1]
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: SCAN TRIGGER ─────────────────────────────────────────
@app.route('/api/scan/trigger', methods=['POST'])
@login_required
def api_scan_trigger():
    try:
        cur = mysql.connection.cursor()
        # Get next scan ID
        cur.execute("SELECT COUNT(*) FROM scan_history")
        count = cur.fetchone()[0]
        scan_id = f"SCN-{str(count + 1).zfill(4)}"
        # Insert new scan as Running
        cur.execute("""
            INSERT INTO scan_history (scan_id, scan_type, scope, status)
            VALUES (%s, %s, %s, 'Running')
        """, (scan_id, 'Full Scan', 'All Assets'))
        mysql.connection.commit()
        # Simulate scan completing — update to Complete
        cur.execute("""
            UPDATE scan_history
            SET status = 'Complete', assets_scanned = %s, vulns_found = %s, critical_count = %s, completed_at = NOW()
            WHERE scan_id = %s
        """, (11, 195, 12, scan_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({'status': 'complete', 'scan_id': scan_id, 'vulns_found': 195})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── DB TEST ───────────────────────────────────────────────────
@app.route('/test-db')
def test_db():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT hostname, ip_address, risk_level FROM assets")
        rows = cur.fetchall()
        cur.close()
        result = [{'hostname': r[0], 'ip': r[1], 'risk': r[2]} for r in rows]
        return jsonify({'status': 'connected', 'assets': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
