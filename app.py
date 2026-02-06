import os
import uuid
import json
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, abort, render_template
from flask import session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

from crypto import encrypt_pii, decrypt_pii, normalize_phone, phone_hash
import secrets

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
mail = Mail(app)

db = SQLAlchemy(app)
# Secret key for session cookies
app.secret_key = os.environ.get('SECRET_KEY') or os.environ.get('FLASK_SECRET') or 'dev-secret'

def send_invite_email(email, username, invite_link):
    if not app.config['MAIL_SERVER']:
        return False
    try:
        msg = Message(subject='Account Invitation', recipients=[email], body=f'Hello,\n\nYou have been invited to join the mutual aid organizing system.\n\nUsername: {username}\n\nClick the link to set your password and claim your account:\n{invite_link}\n\nThis link expires in 7 days.\n\nBest,\nThe Team')
        mail.send(msg)
        return True
    except Exception as e:
        print(f'Email send failed: {e}')
        return False

def send_reset_email(email, username, reset_link):
    if not app.config['MAIL_SERVER']:
        return False
    try:
        msg = Message(subject='Password Reset Request', recipients=[email], body=f'Hello {username},\n\nClick the link to reset your password:\n{reset_link}\n\nThis link expires in 2 hours.\n\nIf you did not request this, ignore this email.\n\nBest,\nThe Team')
        mail.send(msg)
        return True
    except Exception as e:
        print(f'Email send failed: {e}')
        return False


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(30), nullable=False)  # admin, coordinator, volunteer

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    anon_id = db.Column(db.String(36), unique=True, nullable=False)
    encrypted_pii = db.Column(db.LargeBinary, nullable=False)
    phone_hash = db.Column(db.String(64), index=True, nullable=False)
    input_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(30), default='scheduled')
    status_date = db.Column(db.DateTime)
    delivery_date = db.Column(db.DateTime)
    items = db.Column(db.Text)  # JSON string with keys food/nonfood/custom


class ExportLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(80))
    rows = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class UserAudit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))  # actor
    action = db.Column(db.String(80))
    target = db.Column(db.String(80))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class InviteToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, index=True, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(30), default='volunteer')
    created_by = db.Column(db.String(80))
    expires_at = db.Column(db.DateTime)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, index=True, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def get_current_user():
    """Get current user from session or Basic Auth, return None if not authenticated."""
    if 'username' in session:
        uname = session.get('username')
        user = User.query.filter_by(username=uname).first()
        return user
    auth = request.authorization
    if auth:
        user = User.query.filter_by(username=auth.username).first()
        if user and user.check_password(auth.password):
            return user
    return None

def require_auth(role=None):
    # Accept either session-based login or HTTP Basic auth
    user = get_current_user()
    if not user:
        abort(401)
    if role and user.role != role and user.role != 'admin':
        abort(403)
    return user


@app.cli.command('init-db')
def init_db():
    db.create_all()
    print('DB initialized')


@app.cli.command('create-user')
def create_user():
    username = input('username: ')
    pw = input('password: ')
    role = input('role (admin/coordinator/volunteer): ')
    u = User(username=username, password_hash=generate_password_hash(pw), role=role)
    db.session.add(u)
    db.session.commit()
    print('User created')


@app.cli.command('create-admin-from-env')
def create_admin_from_env():
    """Create an admin user non-interactively from ADMIN_USER and ADMIN_PASS env vars."""
    username = os.environ.get('ADMIN_USER')
    pw = os.environ.get('ADMIN_PASS')
    role = os.environ.get('ADMIN_ROLE', 'admin')
    if not username or not pw:
        print('ADMIN_USER and ADMIN_PASS environment variables must be set')
        return
    from werkzeug.security import generate_password_hash
    with app.app_context():
        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f'User "{username}" already exists')
            return
        u = User(username=username, password_hash=generate_password_hash(pw), role=role)
        db.session.add(u)
        db.session.commit()
        print('Created user', username)


@app.route('/intake', methods=['POST'])
def intake():
    user = require_auth()
    data = request.json
    if not data:
        return jsonify({'error': 'JSON required'}), 400
    # Expecting pii fields: name, phone, address, notes
    pii = {k: data.get(k) for k in ('name', 'phone', 'address', 'notes')}
    if not pii.get('phone'):
        return jsonify({'error': 'phone required'}), 400
    ph_norm = normalize_phone(pii['phone'])
    ph_hash = phone_hash(ph_norm)
    exists = Participant.query.filter_by(phone_hash=ph_hash).first()
    if exists:
        return jsonify({'error': 'duplicate_phone', 'found': True, 'anon_id': exists.anon_id}), 409
    # If the provided number is short/partial (e.g. local without area), try suffix-matching
    if len(ph_norm) < 10:
        candidates = Participant.query.limit(200).all()
        for c in candidates:
            try:
                dec = decrypt_pii(c.encrypted_pii)
                stored_phone = dec.get('phone')
                stored_norm = normalize_phone(stored_phone)
                if not stored_norm:
                    continue
                # match if one is suffix of the other (handles local missing area code)
                if stored_norm.endswith(ph_norm) or ph_norm.endswith(stored_norm):
                    return jsonify({'error': 'duplicate_phone', 'found': True, 'anon_id': c.anon_id}), 409
            except Exception:
                continue
    anon = str(uuid.uuid4())
    encrypted = encrypt_pii(pii)
    items = data.get('items', {})
    status = data.get('status', 'scheduled')
    p = Participant(anon_id=anon, encrypted_pii=encrypted, phone_hash=ph_hash,
                    input_by=user.username, status=status, items=json.dumps(items))
    db.session.add(p)
    db.session.commit()
    return jsonify({'anon_id': anon}), 201


@app.route('/volunteer/list', methods=['GET'])
def volunteer_list():
    require_auth()
    parts = Participant.query.all()
    out = []
    for p in parts:
        out.append({
            'anon_id': p.anon_id,
            'items': json.loads(p.items or '{}'),
            'status': p.status,
            'scheduled_date': p.status_date.isoformat() if p.status_date else None,
            'delivery_date': p.delivery_date.isoformat() if p.delivery_date else None,
        })
    return jsonify(out)


@app.route('/volunteer/lookup', methods=['POST'])
def volunteer_lookup():
    user = require_auth(role='coordinator')
    data = request.json
    anon = data.get('anon_id')
    if not anon:
        return jsonify({'error': 'anon_id required'}), 400
    p = Participant.query.filter_by(anon_id=anon).first()
    if not p:
        return jsonify({'error': 'not found'}), 404
    pii = decrypt_pii(p.encrypted_pii)
    return jsonify({'anon_id': anon, 'pii': pii})


@app.route('/lookup/phone', methods=['POST'])
def lookup_by_phone():
    # any authenticated user can check for existence; only admin/coordinator see PII
    user = require_auth()
    data = request.json or {}
    phone = data.get('phone')
    if not phone:
        return jsonify({'error': 'phone required'}), 400
    ph_norm = normalize_phone(phone)
    ph_hash = phone_hash(ph_norm)
    p = Participant.query.filter_by(phone_hash=ph_hash).first()
    if not p:
        return jsonify({'found': False}), 200
    out = {'found': True, 'anon_id': p.anon_id, 'status': p.status, 'items': json.loads(p.items or '{}')}
    if user.role in ('admin', 'coordinator'):
        out['pii'] = decrypt_pii(p.encrypted_pii)
    return jsonify(out)


@app.route('/admin/export-logs', methods=['GET'])
def admin_export_logs():
    user = require_auth(role='admin')
    # pagination and filtering (combine ExportLog and UserAudit)
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 25))
    except Exception:
        page = 1; per_page = 25
    user_filter = request.args.get('user')
    start = request.args.get('start')
    end = request.args.get('end')

    # fetch export logs
    elogs = ExportLog.query
    if user_filter:
        elogs = elogs.filter(ExportLog.username == user_filter)
    if start:
        try:
            elogs = elogs.filter(ExportLog.created_at >= datetime.fromisoformat(start))
        except Exception:
            pass
    if end:
        try:
            elogs = elogs.filter(ExportLog.created_at <= datetime.fromisoformat(end))
        except Exception:
            pass
    elist = elogs.all()

    # fetch user audits
    alogs = UserAudit.query
    if user_filter:
        alogs = alogs.filter((UserAudit.username == user_filter) | (UserAudit.target == user_filter))
    if start:
        try:
            alogs = alogs.filter(UserAudit.created_at >= datetime.fromisoformat(start))
        except Exception:
            pass
    if end:
        try:
            alogs = alogs.filter(UserAudit.created_at <= datetime.fromisoformat(end))
        except Exception:
            pass
    alist = alogs.all()

    combined = []
    for l in elist:
        combined.append({'id': f"E{l.id}", 'username': l.username, 'action': l.action, 'rows': l.rows, 'target': None, 'details': None, 'created_at': l.created_at})
    for a in alist:
        combined.append({'id': f"U{a.id}", 'username': a.username, 'action': a.action, 'rows': None, 'target': a.target, 'details': a.details, 'created_at': a.created_at})

    # sort by created_at desc
    combined.sort(key=lambda x: x['created_at'] or datetime.min, reverse=True)
    total = len(combined)
    start_idx = (page-1)*per_page
    page_items = combined[start_idx:start_idx+per_page]
    out = []
    for it in page_items:
        out.append({'id': it['id'], 'username': it.get('username'), 'action': it.get('action'), 'rows': it.get('rows'), 'target': it.get('target'), 'details': it.get('details'), 'created_at': (it['created_at'].isoformat() if it['created_at'] else None)})
    return jsonify({'total': total, 'page': page, 'per_page': per_page, 'items': out})


@app.route('/admin/export-logs/csv', methods=['POST'])
def admin_export_logs_csv():
    user = require_auth(role='admin')
    data = request.json or {}
    if not data.get('confirm'):
        return jsonify({'error': 'confirmation required'}), 400
    # apply filters
    q = ExportLog.query
    user_filter = data.get('user')
    if user_filter:
        q = q.filter(ExportLog.username == user_filter)
    start = data.get('start')
    end = data.get('end')
    if start:
        try:
            q = q.filter(ExportLog.created_at >= datetime.fromisoformat(start))
        except Exception:
            pass
    if end:
        try:
            q = q.filter(ExportLog.created_at <= datetime.fromisoformat(end))
        except Exception:
            pass
    logs = q.order_by(ExportLog.created_at.desc()).all()
    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['id','username','action','rows','created_at'])
    for l in logs:
        writer.writerow([l.id, l.username, l.action, l.rows, l.created_at.isoformat()])
    si.seek(0)
    # log this export as well
    try:
        log = ExportLog(username=user.username, action='export_logs_csv', rows=len(logs))
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return si.getvalue(), 200, {'Content-Type': 'text/csv'}


@app.route('/ui/export-logs')
def ui_export_logs():
    user = require_auth(role='coordinator')
    return render_template('admin_logs.html', user=user, user_role=user.role)


@app.route('/client-metrics', methods=['POST'])
def client_metrics():
    # Accept client-side performance timings for local debugging only
    try:
        data = request.get_data(as_text=True)
        app.logger.info('Client metrics POST from %s: %s', request.remote_addr, data)
    except Exception as e:
        app.logger.exception('Failed to log client metrics: %s', e)
    return ('', 204)


@app.route('/status/update', methods=['POST'])
def status_update():
    user = require_auth()
    data = request.json
    anon = data.get('anon_id')
    new_status = data.get('status')
    date = data.get('date')
    if not anon or not new_status:
        return jsonify({'error': 'anon_id and status required'}), 400
    p = Participant.query.filter_by(anon_id=anon).first()
    if not p:
        return jsonify({'error': 'not found'}), 404
    p.status = new_status
    if date:
        p.status_date = datetime.fromisoformat(date)
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/export/anonymized', methods=['GET'])
def export_anonymized():
    require_auth(role='coordinator')
    import csv
    from io import StringIO
    parts = Participant.query.all()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['anon_id', 'items', 'status', 'scheduled_date', 'delivery_date'])
    for p in parts:
        writer.writerow([p.anon_id, p.items or '{}', p.status,
                         p.status_date.isoformat() if p.status_date else '',
                         p.delivery_date.isoformat() if p.delivery_date else ''])
    si.seek(0)
    return si.getvalue(), 200, {'Content-Type': 'text/csv'}


@app.route('/export/identifying', methods=['POST'])
def export_identifying():
    user = require_auth(role='admin')
    import csv
    from io import StringIO
    data = request.json or {}
    if not data.get('confirm'):
        return jsonify({'error': 'confirmation required'}), 400
    parts = Participant.query.all()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['anon_id', 'name', 'phone', 'address', 'notes', 'items', 'status'])
    rows = 0
    for p in parts:
        try:
            pii = decrypt_pii(p.encrypted_pii)
            writer.writerow([p.anon_id, pii.get('name'), pii.get('phone'), pii.get('address'), pii.get('notes'), p.items or '{}', p.status])
            rows += 1
        except Exception:
            continue
    si.seek(0)
    # Log the export action
    try:
        log = ExportLog(username=user.username, action='export_identifying', rows=rows)
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return si.getvalue(), 200, {'Content-Type': 'text/csv'}


@app.route('/')
def index():
    user = get_current_user()
    return render_template('landing.html', user=user, user_role=user.role if user else None)


@app.route('/ui/intake')
def ui_intake():
    user = get_current_user()
    return render_template('intake.html', user=user, user_role=user.role if user else None)


@app.route('/ui/volunteer')
def ui_volunteer():
    user = get_current_user()
    return render_template('volunteer.html', user=user, user_role=user.role if user else None)


@app.route('/ui/admin')
def ui_admin():
    user = require_auth(role='coordinator')
    return render_template('admin.html', user=user, user_role=user.role)


@app.route('/ui/users')
def ui_users():
    user = require_auth(role='admin')
    return render_template('admin_users.html', user=user, user_role=user.role)


@app.route('/admin/invite', methods=['POST'])
def admin_create_invite():
    user = require_auth(role='admin')
    data = request.json or {}
    username = data.get('username')
    email = data.get('email')
    role = data.get('role', 'volunteer')
    expires_in = int(data.get('expires_in', 7))
    dev_mode = data.get('dev_mode', False)
    if not username:
        return jsonify({'error': 'username required'}), 400
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=expires_in)
    inv = InviteToken(token=token, username=username, role=role, created_by=user.username, expires_at=expires_at)
    db.session.add(inv)
    try:
        db.session.commit()
        try:
            audit = UserAudit(username=user.username, action='invite_create', target=username, details=json.dumps({'role': role, 'email_sent': bool(email and not dev_mode)}))
            db.session.add(audit)
            db.session.commit()
        except Exception:
            db.session.rollback()
        link = f"{request.host_url.rstrip('/')}/invite/{token}"
        email_sent = False
        if email and not dev_mode:
            email_sent = send_invite_email(email, username, link)
        result = {'invite_link': link, 'username': username}
        if dev_mode or not email_sent:
            result['token'] = token
        return jsonify(result), 201
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'could not create invite'}), 500


@app.route('/invite/<token>', methods=['GET', 'POST'])
def claim_invite(token):
    inv = InviteToken.query.filter_by(token=token).first()
    if not inv or inv.used or (inv.expires_at and inv.expires_at < datetime.utcnow()):
        return render_template('invite_invalid.html'), 404
    if request.method == 'GET':
        return render_template('invite_claim.html', token=token, username=inv.username, role=inv.role)
    # POST - accept password and create user
    data = request.form or request.json or {}
    password = data.get('password')
    if not password:
        return jsonify({'error': 'password required'}), 400
    if User.query.filter_by(username=inv.username).first():
        return jsonify({'error': 'user exists'}), 409
    u = User(username=inv.username, password_hash=generate_password_hash(password), role=inv.role)
    db.session.add(u)
    inv.used = True
    try:
        db.session.commit()
        try:
            audit = UserAudit(username=inv.created_by or 'system', action='user_claimed', target=inv.username, details=json.dumps({'role': inv.role}))
            db.session.add(audit)
            db.session.commit()
        except Exception:
            db.session.rollback()
        return jsonify({'ok': True}), 201
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'could not create user'}), 500


@app.route('/password-reset', methods=['POST'])
def password_reset_request():
    data = request.json or {}
    username = data.get('username')
    email = data.get('email')
    dev_mode = data.get('dev_mode', False)
    if not username:
        return jsonify({'error': 'username required'}), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'not found'}), 404
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=2)
    pr = PasswordReset(token=token, username=username, expires_at=expires_at)
    db.session.add(pr)
    try:
        db.session.commit()
        try:
            audit = UserAudit(username=username, action='password_reset_requested', target=username, details=json.dumps({'email_sent': bool(email and not dev_mode)}))
            db.session.add(audit)
            db.session.commit()
        except Exception:
            db.session.rollback()
        link = f"{request.host_url.rstrip('/')}/password-reset/{token}"
        email_sent = False
        if email and not dev_mode:
            email_sent = send_reset_email(email, username, link)
        result = {'reset_link': link}
        if dev_mode or not email_sent:
            result['token'] = token
        return jsonify(result), 200
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'could not create reset token'}), 500


@app.route('/password-reset/<token>', methods=['GET', 'POST'])
def password_reset_claim(token):
    pr = PasswordReset.query.filter_by(token=token).first()
    if not pr or pr.used or (pr.expires_at and pr.expires_at < datetime.utcnow()):
        return render_template('invite_invalid.html'), 404
    if request.method == 'GET':
        return render_template('password_reset.html', token=token, username=pr.username)
    data = request.form or request.json or {}
    password = data.get('password')
    if not password:
        return jsonify({'error': 'password required'}), 400
    user = User.query.filter_by(username=pr.username).first()
    if not user:
        return jsonify({'error': 'user not found'}), 404
    user.password_hash = generate_password_hash(password)
    pr.used = True
    try:
        db.session.commit()
        try:
            audit = UserAudit(username=pr.username, action='password_reset_completed', target=pr.username, details='')
            db.session.add(audit)
            db.session.commit()
        except Exception:
            db.session.rollback()
        return jsonify({'ok': True})
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'could not reset password'}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'invalid credentials'}), 403
    session['username'] = user.username
    session['role'] = user.role
    try:
        audit = UserAudit(username=user.username, action='login', target=user.username, details='')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'ok': True, 'username': user.username, 'role': user.role})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    user = session.pop('username', None)
    session.pop('role', None)
    if user:
        try:
            audit = UserAudit(username=user, action='logout', target=user, details='')
            db.session.add(audit)
            db.session.commit()
        except Exception:
            db.session.rollback()
    return jsonify({'ok': True})


@app.route('/admin/users', methods=['GET'])
def admin_list_users():
    user = require_auth(role='admin')
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 25))
    except Exception:
        page = 1; per_page = 25
    q = User.query
    search = request.args.get('q')
    if search:
        like = f"%{search}%"
        q = q.filter(User.username.ilike(like))
    total = q.count()
    users = q.order_by(User.username).offset((page-1)*per_page).limit(per_page).all()
    out = [{'username': u.username, 'role': u.role} for u in users]
    return jsonify({'total': total, 'page': page, 'per_page': per_page, 'items': out})


@app.route('/admin/users', methods=['POST'])
def admin_create_user():
    user = require_auth(role='admin')
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'volunteer')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'user exists'}), 409
    u = User(username=username, password_hash=generate_password_hash(password), role=role)
    db.session.add(u)
    db.session.commit()
    # audit
    try:
        audit = UserAudit(username=user.username, action='user_create', target=username, details=json.dumps({'role': role}))
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'ok': True}), 201


@app.route('/admin/users/<username>', methods=['PUT'])
def admin_update_user(username):
    user = require_auth(role='admin')
    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({'error': 'not found'}), 404
    data = request.json or {}
    pw = data.get('password')
    role = data.get('role')
    if pw:
        target.password_hash = generate_password_hash(pw)
    if role:
        target.role = role
    db.session.commit()
    try:
        audit = UserAudit(username=user.username, action='user_update', target=username, details=json.dumps({'role': role, 'password_changed': bool(pw)}))
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'ok': True})


@app.route('/admin/users/<username>', methods=['DELETE'])
def admin_delete_user(username):
    user = require_auth(role='admin')
    if user.username == username:
        return jsonify({'error': 'cannot delete yourself'}), 400
    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(target)
    db.session.commit()
    try:
        audit = UserAudit(username=user.username, action='user_delete', target=username, details='')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'ok': True})



@app.route('/admin/users/import', methods=['POST'])
def admin_import_users():
    user = require_auth(role='admin')
    # Accept multipart form with file field 'file' or raw CSV in body
    file = None
    if 'file' in request.files:
        file = request.files['file']
    else:
        # maybe JSON with csv content
        file_content = request.json and request.json.get('csv')
        if file_content:
            from io import StringIO
            file = StringIO(file_content)
    if not file:
        return jsonify({'error': 'file required'}), 400
    import csv
    from io import StringIO
    results = []
    # Normalize file to text for csv.DictReader
    if hasattr(file, 'read'):
        data = file.read()
        if isinstance(data, bytes):
            text = data.decode('utf-8')
        else:
            text = data
        reader = csv.DictReader(StringIO(text))
    else:
        reader = csv.DictReader(file)
    for row in reader:
        username = (row.get('username') or '').strip()
        password = (row.get('password') or '').strip()
        role = (row.get('role') or 'volunteer').strip()
        if not username:
            continue
        if User.query.filter_by(username=username).first():
            results.append({'username': username, 'status': 'exists'})
            continue
        if not password:
            # generate a simple random password (admin should rotate)
            import secrets
            password = secrets.token_urlsafe(10)
        u = User(username=username, password_hash=generate_password_hash(password), role=role)
        db.session.add(u)
        try:
            db.session.commit()
            results.append({'username': username, 'status': 'created', 'password': password})
            try:
                audit = UserAudit(username=user.username, action='user_create', target=username, details=json.dumps({'role': role}))
                db.session.add(audit)
                db.session.commit()
            except Exception:
                db.session.rollback()
        except Exception:
            db.session.rollback()
            results.append({'username': username, 'status': 'error'})
    return jsonify({'results': results})


if __name__ == '__main__':
    app.run(debug=True)
