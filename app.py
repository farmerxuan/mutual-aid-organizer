import os
import uuid
import json
from datetime import datetime

from flask import Flask, request, jsonify, abort, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from crypto import encrypt_pii, decrypt_pii, normalize_phone, phone_hash

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


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


def require_auth(role=None):
    auth = request.authorization
    if not auth:
        abort(401)
    user = User.query.filter_by(username=auth.username).first()
    if not user or not user.check_password(auth.password):
        abort(403)
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
    # pagination and filtering
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 25))
    except Exception:
        page = 1; per_page = 25
    q = ExportLog.query
    user_filter = request.args.get('user')
    if user_filter:
        q = q.filter(ExportLog.username == user_filter)
    start = request.args.get('start')
    end = request.args.get('end')
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
    total = q.count()
    logs = q.order_by(ExportLog.created_at.desc()).offset((page-1)*per_page).limit(per_page).all()
    out = []
    for l in logs:
        out.append({'id': l.id, 'username': l.username, 'action': l.action, 'rows': l.rows, 'created_at': l.created_at.isoformat()})
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
    user = require_auth(role='admin')
    return render_template('admin_logs.html')


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
    return render_template('index.html')


@app.route('/ui/intake')
def ui_intake():
    return render_template('intake.html')


@app.route('/ui/volunteer')
def ui_volunteer():
    return render_template('volunteer.html')


@app.route('/ui/admin')
def ui_admin():
    return render_template('admin.html')


if __name__ == '__main__':
    app.run(debug=True)
