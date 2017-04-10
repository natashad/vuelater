from flask import Flask, request, g, jsonify
from flask_cors import CORS, cross_origin
from flask_restful import abort, Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth

from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

from passlib.apps import custom_app_context as pwd_context

app = Flask(__name__)
auth = HTTPBasicAuth()

app.config['SECRET_KEY'] = 'Very secret key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
CORS(app)

api = Api(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    password_hash = db.Column(db.String(128))

    def __init__(self, email, first_name, last_name):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name

    def __repr__(self):
        return "<User {}: {} {} {}>".format(self.id, self.email, self.first_name, self.last_name)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password+self.email)

    def verify_password(self, password):
        return pwd_context.verify(password+self.email, self.password_hash)

    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def generate_auth_token(self, expiration = 3600):
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.query.get(data['id'])
        return user

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, db.ForeignKey("user.id"))
    sender = db.Column(db.Integer, db.ForeignKey("user.id"))
    url = db.Column(db.String(80))
    note = db.Column(db.String(256))
    duration = db.Column(db.String(10))
    item_type = db.Column(db.String(80))

    def __init__(self, owner, sender, url, note = '', duration = '', item_type = ''):
        self.owner = owner
        self.sender = sender
        self.url = url
        self.note = note
        self.duration = duration
        self.item_type = item_type

    def __repr__(self):
        return "<Item {} {} {} {}>".format(self.id, self.owner, self.sender, self.url)

    def as_dict(self):
        return {
            'id'       : self.id, 
            'owner'    : User.query.get(self.owner).email, 
            'sender'   : User.query.get(self.sender).email,
            'url'      : self.url,
            'note'     : self.note,
            'duration' : self.duration,
            'type'     : self.item_type

        }

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_from = db.Column(db.Integer, db.ForeignKey("user.id"))
    user_to = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __init__(self, user_from, user_to):
        self.user_from = user_from
        self.user_to = user_to

    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

def abort_if_id_doesnt_exist(dic, id):
    if id not in dic:
        abort(404, message="id {} doesn't exist".format(id))

@auth.verify_password
def verify_password(email_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(email_or_token)
    if not user:
        # try to authenticate with email/password
        user = User.query.filter_by(email = email_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/login')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({ 'token': token.decode('ascii') })

class UserAPI(Resource):
    def get(self, user_id):
        user = User.query.get(user_id)
        if user is None:
            abort(404, message="User {} doesn't exist".format(user_id))
        return user.as_dict(), 200

    def put(self, user_id):
        user = User.query.get(user_id)
        if user is None:
            abort(404, message="User {} doesn't exist".format(user_id))
        user.email = request.form['email']
        db.session.add(user)
        db.session.commit()
        return user.as_dict(), 201

    def delete(self, user_id):
        user = User.query.get(user_id)
        if user is None:
            abort(404, message="User {} doesn't exist".format(user_id))
        db.session.delete(user)
        db.session.commit()
        return "", 204

class UsersAPI(Resource):
    def get(self):
        return [e.as_dict() for e in User.query.all()]

    def post(self):
        email = request.json.get('email')
        password = request.json.get('password')
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')

        if email is None or password is None or first_name is None or last_name is None:
            abort(400) # missing arguments
        if User.query.filter_by(email = email).first() is not None:
            abort(400) # existing user
        user = User(email, first_name, last_name)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()
        return {'status': 'OK'}, 201

class ItemAPI(Resource):
    def get(self, item_id):
        item = Item.query.get(item_id)
        if item is None:
            abort(404, message="Item {} doesn't exist".format(item_id))
        return item.as_dict(), 200

    @auth.login_required
    def put(self, item_id):
        item = Item.query.get(item_id)
        if item is None:
            abort(404, message="Item {} doesn't exist".format(item_id))
        
        owner = request.json.get('owner')
        user = User.query.get(owner)
        if user is None:
            abort(404, message="User {} doesn't exist".format(owner))
        
        item.url = request.json.get('url')
        item.owner = owner
        db.session.add(item)
        db.session.commit()
        return item.as_dict(), 201

    @auth.login_required
    def delete(self, item_id):
        item = Item.query.get(item_id)
        if item is None:
            abort(404, message="Item {} doesn't exist".format(item_id))
        db.session.delete(item)
        db.session.commit()
        return "", 204

class ItemsAPI(Resource):
    def get(self):
        return [e.as_dict() for e in Item.query.all()]

    @auth.login_required
    def post(self):
        #TODO check if friends?
        owner = request.json.get('owner')
        user = User.query.filter_by(email=owner).first()
        if user is None:
            abort(404, message="User {} doesn't exist".format(owner))
        note = '' if request.json.get('note') is None else request.json.get('note')
        duration = '' if request.json.get('duration') is None else request.json.get('duration')
        item_type = '' if request.json.get('type') is None else request.json.get('type')
        item = Item(user.id, g.user.id, request.json.get('url'), note, duration, item_type)
        db.session.add(item)
        db.session.commit()
        return {'status': 'OK'}, 201

class InboxAPI(Resource):
    @auth.login_required
    def get(self):
        return [e.as_dict() for e in Item.query.filter_by(owner=g.user.id).all()]

class OutboxAPI(Resource):
    @auth.login_required
    def get(self):
        return [e.as_dict() for e in Item.query.filter_by(sender=g.user.id).all()]

class FriendsAPI(Resource):
    @auth.login_required
    def get(self):
        return [User.query.get(e.user_to).email for e in Item.query.filter_by(user_from=g.user.id).all()]

    @auth.login_required
    def post(self):
        friendee = request.json.get('friendee')
        user = User.query.filter_by(email=friendee).first()
        if user is None:
            abort(404, message="User {} doesn't exist".format(owner))
        friend = Item(g.user.id, user.id)
        db.session.add(friend)
        db.session.commit()
        return {'status': 'OK'}, 201

class FollowersAPI(Resource):
    @auth.login_required
    def get(self):
        return [User.query.get(e.user_from).username for e in Item.query.filter_by(user_to=g.user.id).all()]

api.add_resource(UserAPI, '/user/<int:user_id>')
api.add_resource(UsersAPI, '/users')

api.add_resource(ItemAPI, '/item/<int:item_id>')
api.add_resource(ItemsAPI, '/items')

api.add_resource(FriendsAPI, '/friends')
api.add_resource(FollowersAPI, '/followers')

api.add_resource(InboxAPI, '/inbox')
api.add_resource(OutboxAPI, '/outbox')

# TODO connections (pairs of user ids)

# TODO outbox
# TODO login

if __name__ == '__main__':
    app.run(debug=True)