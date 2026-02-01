import os
import json
import base64
from werkzeug.security import generate_password_hash

os.environ['SECRET_KEY'] = base64.b64encode(__import__('os').urandom(32)).decode()

from app import app, db, User


def setup_module(module):
    with app.app_context():
        db.drop_all()
        db.create_all()
        # create users
        admin = User(username='ciadmin', password_hash=generate_password_hash('adminpass'), role='admin')
        coord = User(username='cicoord', password_hash=generate_password_hash('coordpass'), role='coordinator')
        vol = User(username='civol', password_hash=generate_password_hash('volpass'), role='volunteer')
        db.session.add_all([admin, coord, vol])
        db.session.commit()


def auth_header(user, pw):
    return {'Authorization': 'Basic ' + base64.b64encode(f"{user}:{pw}".encode()).decode(), 'Content-Type':'application/json'}


def test_intake_and_exports():
    client = app.test_client()
    p1 = {'name':'CI Test','phone':'+1 555-0200','address':'1 CI Ave','items':[{'category':'food','name':'bread','qty':'1'}],'status':'new'}
    r1 = client.post('/intake', headers=auth_header('ciadmin','adminpass'), data=json.dumps(p1))
    assert r1.status_code == 201

    # duplicate should be rejected
    p2 = {'name':'CI Dup','phone':'(555) 0200','address':'1 CI Ave','items':[]}
    r2 = client.post('/intake', headers=auth_header('ciadmin','adminpass'), data=json.dumps(p2))
    assert r2.status_code == 409

    # anonymized export as coordinator
    ranon = client.get('/export/anonymized', headers=auth_header('cicoord','coordpass'))
    assert ranon.status_code == 200

    # identifying export as admin (POST confirm)
    rident = client.post('/export/identifying', headers=auth_header('ciadmin','adminpass'), data=json.dumps({'confirm':True}))
    assert rident.status_code == 200
