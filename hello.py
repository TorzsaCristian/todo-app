from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb:/root:root@localhost/myappdatabase'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key = True)
    data = db.Column(db.String(255))

    def __init__(self, data):
        self.id = 0
        self.data = data


@app.route('/')
def index():
    temp = Comment("WTFFFF")
    db.session.add(temp)
    db.session.commit()
    com = Comment.query.all()
    return jsonify({'response': com[0].data})
