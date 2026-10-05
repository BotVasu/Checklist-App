import os
import json
import sqlite3
import re
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = Flask(__name__)
app.secret_key = "sec_assessment_super_secret_key"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DB_PATH = 'database/security_app.db'
CHECKLISTS_DIR = 'checklist'

os.makedirs('database', exist_ok=True)
os.makedirs('reports', exist_ok=True)

def check_malicious_input(text):
    """Detects low-effort malicious payloads and returns a playful ego-bruising message."""
    if not text:
        return None
        
    # Common attack signatures (XSS, Script injection, SQLi attempts)
    patterns = [
        r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'UNION\s+SELECT',
        r'DROP\s+TABLE',
        r'<iframe',
        r'eval\s*\('
    ]
    
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return "Nice try, but you can do better than that! Try a more sophisticated payload."
            
    return None




# Database Initialization
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            app_type TEXT NOT NULL,
            app_url TEXT NOT NULL,
            tester_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(tester_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assessment_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER,
            item_id TEXT NOT NULL,
            category TEXT NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            notes TEXT DEFAULT '',
            FOREIGN KEY(assessment_id) REFERENCES assessments(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS custom_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_type TEXT NOT NULL,
            item_id TEXT NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            how_to_test TEXT
        )
    ''')
    
    # Create default admin user if none exists
    cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
    if cursor.fetchone()[0] == 0:
        hashed_pwd = generate_password_hash('Admin@123')
        cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', ('admin', hashed_pwd, 1))
        
    # Create default tester user if none exists
    cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('tester',))
    if cursor.fetchone()[0] == 0:
        hashed_pwd = generate_password_hash('Tester@123')
        cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', ('tester', hashed_pwd, 0))

    conn.commit()
    conn.close()

init_db()

class User(UserMixin):
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], is_admin=user[2])
    return None

def load_checklist_json(app_type):
    file_path = os.path.join(CHECKLISTS_DIR, f"{app_type}.json")
    items = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            data = json.load(f)
            category_name = data.get("category", app_type.upper())
            for item in data.get("items", []):
                item['category'] = category_name
                items.append(item)
                
    # Append custom vulnerabilities added by admin
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT item_id, name, severity, description, how_to_test FROM custom_vulnerabilities WHERE app_type = ?', (app_type,))
    custom_rows = cursor.fetchall()
    conn.close()
    
    for row in custom_rows:
        items.append({
            "id": row[0],
            "name": row[1],
            "severity": row[2],
            "description": row[3],
            "how_to_test": row[4],
            "category": f"Custom ({app_type.upper()})"
        })
        
    return items

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password, is_admin FROM users WHERE username = ?', (username,))
        user_row = cursor.fetchone()
        conn.close()
        
        if user_row and check_password_hash(user_row[2], password):
            user = User(id=user_row[0], username=user_row[1], is_admin=user_row[3])
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Ego-hurting authentication failure message
            flash('Authentication failed! Wrong credentials? Even a script kiddie could do better than that. Try again!', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if current_user.is_admin:
        cursor.execute('''
            SELECT a.id, a.name, a.app_type, a.app_url, a.created_at, u.username 
            FROM assessments a JOIN users u ON a.tester_id = u.id ORDER BY a.created_at DESC
        ''')
    else:
        cursor.execute('''
            SELECT a.id, a.name, a.app_type, a.app_url, a.created_at, u.username 
            FROM assessments a JOIN users u ON a.tester_id = u.id WHERE a.tester_id = ? ORDER BY a.created_at DESC
        ''', (current_user.id,))
    assessments = cursor.fetchall()
    
    # Calculate summary stats for each assessment
    assessment_summaries = []
    for asm in assessments:
        asm_id = asm[0]
        cursor.execute('SELECT status, severity FROM assessment_items WHERE assessment_id = ?', (asm_id,))
        items = cursor.fetchall()
        total = len(items)
        passed = sum(1 for i in items if i[0] == 'Passed')
        failed = sum(1 for i in items if i[0] == 'Failed')
        na = sum(1 for i in items if i[0] == 'N/A')
        pending = sum(1 for i in items if i[0] == 'Pending')
        pct = int((passed + failed + na) / total * 100) if total > 0 else 0
        assessment_summaries.append({
            'id': asm_id,
            'name': asm[1],
            'app_type': asm[2],
            'app_url': asm[3],
            'created_at': asm[4],
            'tester': asm[5],
            'total': total,
            'passed': passed,
            'failed': failed,
            'na': na,
            'pending': pending,
            'pct': pct
        })
    conn.close()
    return render_template('dashboard.html', assessments=assessment_summaries)

@app.route('/assessment/create', methods=['GET', 'POST'])
@login_required
def create_assessment():
    if request.method == 'POST':
        name = request.form.get('name')
        app_type = request.form.get('app_type')
        app_url = request.form.get('app_url')
        
        if not name or not app_type or not app_url:
            flash('All fields are required!', 'danger')
            return redirect(url_for('create_assessment'))
# Ego-hurting validation check
        for field_name, val in [("Assessment Name", name), ("Application URL", app_url)]:
            error_msg = check_malicious_input(val)
            if error_msg:
                flash(f"⚠️ {field_name}: {error_msg} You can do better than that!", 'danger')
                return redirect(url_for('create_assessment'))
            
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO assessments (name, app_type, app_url, tester_id) VALUES (?, ?, ?, ?)',
                       (name, app_type, app_url, current_user.id))
        assessment_id = cursor.lastrowid
        
        # Load checklist items from JSON and custom DB
        checklist_items = load_checklist_json(app_type)
        for item in checklist_items:
            cursor.execute('''
                INSERT INTO assessment_items (assessment_id, item_id, category, name, severity, status, notes)
                VALUES (?, ?, ?, ?, ?, 'Pending', '')
            ''', (assessment_id, item['id'], item['category'], item['name'], item['severity']))
            
        conn.commit()
        conn.close()
        flash('Security Assessment created successfully!', 'success')
        return redirect(url_for('view_assessment', assessment_id=assessment_id))
        
    return render_template('create_assessment.html')

@app.route('/assessment/<int:assessment_id>')
@login_required
def view_assessment(assessment_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, app_type, app_url, created_at FROM assessments WHERE id = ?', (assessment_id,))
    asm = cursor.fetchone()
    if not asm:
        conn.close()
        flash('Assessment not found.', 'danger')
        return redirect(url_for('dashboard'))
        
    cursor.execute('SELECT id, item_id, category, name, severity, status, notes FROM assessment_items WHERE assessment_id = ?', (assessment_id,))
    db_items = cursor.fetchall()
    
    json_items = load_checklist_json(asm[2])
    json_meta = {item['id']: {'description': item.get('description', ''), 'how_to_test': item.get('how_to_test', '')} for item in json_items}
    
    items = []
    categorized_items = {}
    
    for row in db_items:
        meta = json_meta.get(row[1], {'description': 'No description provided.', 'how_to_test': 'Refer to standard security guidelines.'})
        item_obj = {
            'db_id': row[0],
            'item_id': row[1],
            'category': row[2],
            'name': row[3],
            'severity': row[4],
            'status': row[5],
            'notes': row[6],
            'description': meta['description'],
            'how_to_test': meta['how_to_test']
        }
        items.append(item_obj)
        
        # Group by category for the UI accordions
        cat = row[2]
        if cat not in categorized_items:
            categorized_items[cat] = []
        categorized_items[cat].append(item_obj)
        
    conn.close()
    return render_template('assessment_view.html', assessment={'id': asm[0], 'name': asm[1], 'app_type': asm[2], 'app_url': asm[3], 'created_at': asm[4]}, items=items, categorized_items=categorized_items)

@app.route('/api/update_item', methods=['POST'])
@login_required
def update_item():
    data = request.json
    db_id = data.get('db_id')
    status = data.get('status')
    notes = data.get('notes')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if not current_user.is_admin:
        cursor.execute('''
            SELECT a.tester_id FROM assessment_items ai 
            JOIN assessments a ON ai.assessment_id = a.id 
            WHERE ai.id = ?
        ''', (db_id,))
        row = cursor.fetchone()
        if not row or row[0] != current_user.id:
            conn.close()
            return jsonify({'success': False, 'error': 'Unauthorized! Trying to modify another user’s records? You can do better than that!'}), 403

    if status is not None:
        cursor.execute('UPDATE assessment_items SET status = ? WHERE id = ?', (status, db_id))
    if notes is not None:
        error_msg = check_malicious_input(notes)
        if error_msg:
            conn.close()
            return jsonify({'success': False, 'error': f"Nice try! {error_msg} You can do better than that."}), 400
        cursor.execute('UPDATE assessment_items SET notes = ? WHERE id = ?', (notes, db_id))
        
    conn.commit()
    
    cursor.execute('SELECT assessment_id FROM assessment_items WHERE id = ?', (db_id,))
    res = cursor.fetchone()
    assessment_id = res[0] if res else None
    
    progress = {}
    item_statuses = {}
    if assessment_id:
        cursor.execute('SELECT id, status FROM assessment_items WHERE assessment_id = ?', (assessment_id,))
        items = cursor.fetchall()
        total = len(items)
        passed = sum(1 for i in items if i[1] == 'Passed')
        failed = sum(1 for i in items if i[1] == 'Failed')
        na = sum(1 for i in items if i[1] == 'N/A')
        pending = sum(1 for i in items if i[1] == 'Pending')
        pct = int((passed + failed + na) / total * 100) if total > 0 else 0
        progress = {'total': total, 'passed': passed, 'failed': failed, 'na': na, 'pending': pending, 'pct': pct}
        
        # Map every item ID to its latest status for the sidebar
        for item_db_id, item_status in items:
            item_statuses[item_db_id] = item_status
            
    conn.close()
    return jsonify({'success': True, 'progress': progress, 'item_statuses': item_statuses})

@app.route('/api/bulk_update', methods=['POST'])
@login_required
def bulk_update():
    data = request.json
    assessment_id = data.get('assessment_id')
    status = data.get('status')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE assessment_items SET status = ? WHERE assessment_id = ? AND status = "Pending"', (status, assessment_id))
    conn.commit()
    
    cursor.execute('SELECT status, severity FROM assessment_items WHERE assessment_id = ?', (assessment_id,))
    items = cursor.fetchall()
    total = len(items)
    passed = sum(1 for i in items if i[0] == 'Passed')
    failed = sum(1 for i in items if i[0] == 'Failed')
    na = sum(1 for i in items if i[0] == 'N/A')
    pending = sum(1 for i in items if i[0] == 'Pending')
    pct = int((passed + failed + na) / total * 100) if total > 0 else 0
    conn.close()
    
    return jsonify({'success': True, 'progress': {'total': total, 'passed': passed, 'failed': failed, 'na': na, 'pending': pending, 'pct': pct}})

@app.route('/assessment/delete/<int:assessment_id>', methods=['POST'])
@login_required
def delete_assessment(assessment_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT tester_id FROM assessments WHERE id = ?', (assessment_id,))
    row = cursor.fetchone()
    
    if row and (current_user.is_admin or row[0] == current_user.id):
        cursor.execute('DELETE FROM assessment_items WHERE assessment_id = ?', (assessment_id,))
        cursor.execute('DELETE FROM assessments WHERE id = ?', (assessment_id,))
        conn.commit()
        flash('Assessment deleted successfully.', 'success')
    else:
        # Authorization failure with ego-bruising feedback
        flash('Authorization Error: Nice IDOR / Privilege Escalation attempt, but you can do better than that! You do not own this assessment.', 'danger')
        
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/assessment/export_pdf/<int:assessment_id>')
@login_required
def export_pdf(assessment_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT name, app_type, app_url, created_at FROM assessments WHERE id = ?', (assessment_id,))
    asm = cursor.fetchone()
    if not asm:
        conn.close()
        flash('Assessment not found.', 'danger')
        return redirect(url_for('dashboard'))
        
    cursor.execute('SELECT item_id, category, name, severity, status, notes FROM assessment_items WHERE assessment_id = ?', (assessment_id,))
    items = cursor.fetchall()
    conn.close()
    
    pdf_path = f"reports/Assessment_Report_{assessment_id}.pdf"
    doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#1e293b'), spaceAfter=6)
    subtitle_style = ParagraphStyle('ReportSub', parent=styles['Normal'], fontSize=11, textColor=colors.HexColor('#64748b'), spaceAfter=15)
    section_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#0f172a'), spaceBefore=15, spaceAfter=8)
    cell_style = ParagraphStyle('CellText', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#334155'))
    header_style = ParagraphStyle('HeaderCell', parent=styles['Normal'], fontSize=9, textColor=colors.white, fontName='Helvetica-Bold')

    story = []
    story.append(Paragraph(f"Security Assessment Report", title_style))
    story.append(Paragraph(f"<b>Application:</b> {asm[0]} | <b>Type:</b> {asm[1].upper()} | <b>URL:</b> {asm[2]} | <b>Date:</b> {asm[3]}", subtitle_style))
    story.append(Spacer(1, 10))
    
    # Summary Table
    total = len(items)
    passed = sum(1 for i in items if i[4] == 'Passed')
    failed = sum(1 for i in items if i[4] == 'Failed')
    na = sum(1 for i in items if i[4] == 'N/A')
    pending = sum(1 for i in items if i[4] == 'Pending')
    
    summary_data = [
        [Paragraph('<b>Total Tests</b>', header_style), Paragraph('<b>Passed</b>', header_style), Paragraph('<b>Failed</b>', header_style), Paragraph('<b>N/A</b>', header_style), Paragraph('<b>Pending</b>', header_style)],
        [Paragraph(str(total), cell_style), Paragraph(str(passed), cell_style), Paragraph(str(failed), cell_style), Paragraph(str(na), cell_style), Paragraph(str(pending), cell_style)]
    ]
    t_summary = Table(summary_data, colWidths=[100, 100, 100, 100, 100])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1'))
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 15))
    
    # Vulnerabilities Table (Failed items or full checklist)
    story.append(Paragraph("Detailed Test Results & Vulnerability Log", section_style))
    
    table_data = [[
        Paragraph('<b>ID</b>', header_style),
        Paragraph('<b>Check Name</b>', header_style),
        Paragraph('<b>Severity</b>', header_style),
        Paragraph('<b>Status</b>', header_style),
        Paragraph('<b>Notes</b>', header_style)
    ]]
    
    for item in items:
        sev_color = '#dc2626' if item[3] == 'Critical' else ('#f97316' if item[3] == 'High' else '#eab308')
        table_data.append([
            Paragraph(item[0], cell_style),
            Paragraph(item[2], cell_style),
            Paragraph(f"<font color='{sev_color}'><b>{item[3]}</b></font>", cell_style),
            Paragraph(item[4], cell_style),
            Paragraph(item[5] if item[5] else '-', cell_style)
        ])
        
    t_vuln = Table(table_data, colWidths=[65, 160, 65, 65, 185])
    t_vuln.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(t_vuln)
    
    doc.build(story)
    return send_file(pdf_path, as_attachment=True, download_name=f"Security_Assessment_{assessment_id}.pdf")

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_portal():
    if not current_user.is_admin:
        # Ego-bruising authorization message for broken access control attempts
        flash('Access Denied! Trying to perform unauthorized privilege escalation? You can definitely do better than that!', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create_user':
            username = request.form.get('new_username')
            password = request.form.get('new_password')
            is_admin = 1 if request.form.get('is_admin') == 'on' else 0
            if username and password:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                                   (username, generate_password_hash(password), is_admin))
                    conn.commit()
                    conn.close()
                    flash(f'User "{username}" created successfully.', 'success')
                except sqlite3.IntegrityError:
                    flash('Username already exists.', 'danger')
            else:
                flash('Username and password are required.', 'danger')
                
        elif action == 'add_vulnerability':
            app_type = request.form.get('app_type')
            item_id = request.form.get('item_id')
            name = request.form.get('name')
            severity = request.form.get('severity')
            description = request.form.get('description')
            how_to_test = request.form.get('how_to_test')
# Check inputs against low-effort payloads
            for field_name, val in [("Name", name), ("Description", description), ("How to Test", how_to_test)]:
                error_msg = check_malicious_input(val)
                if error_msg:
                    flash(f"⚠️ {field_name}: {error_msg} Seriously, you can do better than that.", 'danger')
                    return redirect(url_for('admin_portal'))
            
            if app_type and item_id and name and severity:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                try:
                    cursor.execute('''
                        INSERT INTO custom_vulnerabilities (app_type, item_id, name, severity, description, how_to_test)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (app_type, item_id, name, severity, description, how_to_test))
                    conn.commit()
                    flash(f'Custom vulnerability "{name}" added successfully to {app_type.upper()} checklists.', 'success')
                except Exception as e:
                    flash(f'Error adding vulnerability: {e}', 'danger')
                finally:
                    conn.close()
            else:
                flash('Required fields for custom vulnerability missing.', 'danger')
                
        return redirect(url_for('admin_portal'))
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, is_admin FROM users')
    users = cursor.fetchall()
    
    cursor.execute('SELECT id, app_type, item_id, name, severity FROM custom_vulnerabilities')
    custom_vulns = cursor.fetchall()
    conn.close()
    
    return render_template('admin.html', users=users, custom_vulns=custom_vulns)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
