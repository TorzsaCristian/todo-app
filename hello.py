import json
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, abort, jsonify, request, url_for, g
from sqlalchemy.exc import IntegrityError
from flask.json import JSONEncoder
from flask_login import LoginManager, UserMixin
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

class MyJSONEncoder(JSONEncoder):
	def default(self, obj):
		if isinstance(obj, Users):
			return {
				'id': obj.id,
				'name': obj.name
			}
		return super(MyJSONEncoder, self).default(obj)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'to quick brown fox jumps over the lazy fucking mothafucka dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://root:root@localhost/todo_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json_encoder = MyJSONEncoder

db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
	__tablename__ = 'users'
	id = db.Column('id', db.Integer, primary_key = True)
	username = db.Column('username', db.String(255), index=True)
	password_hash = db.Column('password_hash', db.String(128))

	def __init__(self, username):
		self.username = username

	def hash_password(self, password):
		self.password_hash = pwd_context.encrypt(password)

	def verify_password(self, password):
		return pwd_context.verify(password, self.password_hash)

	def generate_auth_token(self, expiration=600):
		s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
		return s.dumps({'id': self.id})

	@staticmethod
	def verify_auth_token(token):
		s = Serializer(app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except SignatureExpired:
			return None #valid token, but expired
		except BadSignature:
			return None #invalid token
		user = User.query.get(data['id'])
		return user

@auth.verify_password
def verify_password(username_or_token, password):
	#first we try to autenticate by token
	user = User.verify_auth_token(username_or_token)
	if not user:
		#try to authenticate with username/password
		user = User.query.filter_by(username=username_or_token).first()
		if not user or not user.verify_password(password):
			return False
	g.user = user
	return True


@app.route('/users/<int:id>')
def get_user():
	user = User.query.get(id)
	if not user:
		abort(400)
	return jsonify({'username': user.username})


@app.route('/users', methods=['POST'])
def new_user():
	username = request.form['username']
	password = request.form['password']
	if username is None or password is None:
		abort(400); #missing arguments
	if User.query.filter_by(username=username).first() is not None:
		abort(400) #existing user
	user = User(username)
	user.hash_password(password)
	db.session.add(user)
	db.session.commit()
	return jsonify({'username': user.username}),201 #, {'location': url_for('get_user', id = user.id, _external = True)};


@app.route('/login')
@auth.login_required
def get_auth_token():
	token = g.user.generate_auth_token(600)
	return jsonify({'message': 'SUCCES', 'username': g.user.username,'token': token.decode('ascii')})


@app.route('/resource')
@auth.login_required
def get_resource():
	return jsonify({'data': 'Hello, %s!!' % g.user.username})

