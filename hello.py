import json
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, abort, jsonify, request, url_for, g
from sqlalchemy.exc import IntegrityError
from flask.json import JSONEncoder
from flask_login import LoginManager, UserMixin
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'to quick brown fox jumps over the lazy fucking mothafucka dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://root:root@localhost/todo_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json_encoder = JSONEncoder

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

class Note(db.Model):
	__tablename__ = 'notes'
	id = db.Column(db.Integer, primary_key = True)
	user_id = db.Column(db.Integer)
	title = db.Column(db.String)
	description = db.Column(db.String)
	
	def to_json(self):
		return{
			'id': self.id,
			'user_id': self.user_id,
			'title': self.title,
			'description': self.description
		}
		
	def from_json(self, source):
		if 'user_id' in source:
			self.user_id = source['user_id']
		if 'title' in source:
			self.title = source['title']
		if 'description' in source:
			self.description = source['description']


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


@app.route('/notes/', methods=['GET', 'POST', 'PUT'])
@auth.login_required
def get_notes():
	if request.method == 'GET':
		user_id = request.args.get('user_id')
		notes = Note.query.filter(Note.user_id==user_id).all()
		result = []
		for note in notes:
			result.append(note.to_json())
		return jsonify(result)
	elif request.method == 'POST':
		note = Note()
		posted_json = {'user_id': request.form['user_id'],'title':  request.form['title'], 'description':  request.form['description']}
		note.from_json(posted_json)
		db.session.add(note)
		db.session.commit()
		#return jsonify({'message': 'Note added succesfully!', 'code': '200'})
		return jsonify({'note': note.to_json(), 'message': 'Note added succesfully!', 'code': 200})
	elif request.method == 'PUT':
		note_id = request.form['note_id']
		note = Note.query.filter(Note.id==note_id).first()
		note.title = request.form['title']
		note.description = request.form['description']
		db.session.commit()
		return jsonify({'note': note.to_json(), 'message': 'Note updated succesfully!', 'code':200})



@app.route('/login')
@auth.login_required
def get_auth_token():
	token = g.user.generate_auth_token(600)
	return jsonify({'message': 'SUCCES', 'username': g.user.username,'token': token.decode('ascii'), 'user_id': g.user.id})


@app.route('/cacat', methods=['POST'])
@auth.login_required
def get_resource():
	pass
