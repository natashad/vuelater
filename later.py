from flask import Flask, request
from flask_restful import abort, Resource, Api
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

api = Api(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)

    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return "<User {}: {}>".format(self.id, self.username)

    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, db.ForeignKey("user.id"))
    url = db.Column(db.String(80))

    def __init__(self, owner, url):
        self.owner = owner
        self.url = url

    def __repr__(self):
        return "<Item {} {} {}>".format(self.id, self.owner, self.url)

    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

def abort_if_id_doesnt_exist(dic, id):
    if id not in dic:
        abort(404, message="id {} doesn't exist".format(id))

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
        user.username = request.form['name']
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
        user = User(request.form['name'])
        db.session.add(user)
        db.session.commit()
        return user.as_dict(), 201

class ItemAPI(Resource):
    def get(self, item_id):
        item = Item.query.get(item_id)
        if item is None:
            abort(404, message="Item {} doesn't exist".format(item_id))
        return item.as_dict(), 200

    def put(self, item_id):
        item = Item.query.get(item_id)
        if item is None:
            abort(404, message="Item {} doesn't exist".format(item_id))
        
        owner = request.form['owner']
        user = User.query.get(owner)
        if user is None:
            abort(404, message="User {} doesn't exist".format(owner))
        
        item.url = request.form['url']
        item.owner = owner
        db.session.add(item)
        db.session.commit()
        return item.as_dict(), 201

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

    def post(self):
        owner = request.form['owner']
        user = User.query.get(owner)
        if user is None:
            abort(404, message="User {} doesn't exist".format(owner))
        item = Item(owner, request.form['url'])
        db.session.add(item)
        db.session.commit()
        return item.as_dict(), 201

class InboxAPI(Resource):
    def get(self, user_id):
        user = User.query.get(user_id)
        if user is None:
            abort(404, message="User {} doesn't exist".format(user_id))
        return [e.as_dict() for e in Item.query.filter_by(owner=user.id).all()]

api.add_resource(UserAPI, '/user/<int:user_id>')
api.add_resource(UsersAPI, '/users')

api.add_resource(ItemAPI, '/item/<int:item_id>')
api.add_resource(ItemsAPI, '/items')

api.add_resource(InboxAPI, '/inbox/<int:user_id>')

if __name__ == '__main__':
    app.run(debug=True)