# Import necessary modules and libraries
from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from marshmallow import Schema, fields, validate, ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
import re
import logging

# Configuration class for app settings
class Config:
    SECRET_KEY = 'mysecret'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# Initialize Flask app and load configuration from the Config class
app = Flask(__name__)
app.config.from_object(Config)

# Initialize SQLAlchemy for database management
db = SQLAlchemy(app)

# Initialize Flask-RESTful API
api = Api(app)

# Initialize JWT Manager for handling JWT tokens
jwt = JWTManager(app)

# Connect to Redis for rate limiting storage
redis_connection = Redis(host='localhost', port=6379)

# Initialize Flask-Limiter using Redis as storage backend
limiter = Limiter(key_func=get_remote_address, storage_uri="redis://localhost:6379")

# Attach Limiter to the app
limiter.init_app(app)

# Logging for tracking user activities
logging.basicConfig(filename='app.log', level=logging.INFO)

# Input validation schema using Marshmallow
class UserSchema(Schema):
    username = fields.String(required=True, validate=validate.Length(min=4, max=80))
    password = fields.String(required=True, validate=validate.Length(min=8))

class ItemSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1, max=80))
    description = fields.String(validate=validate.Length(max=200))

user_schema = UserSchema()
item_schema = ItemSchema()

# Helper function for password complexity check
def validate_password(password):
    """
    Validates password complexity: length, upper, lower, digit, special char
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search("[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search("[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search("[0-9]", password):
        return False, "Password must contain at least one number"
    if not re.search("[@#$%^&+=!]", password):
        return False, "Password must contain at least one special character"
    return True, ""

# Censorship function for usernames (simple blacklist)
def censor_username(username):
    """
    Simple censorship for offensive words in username.
    """
    offensive_words = ['badword1', 'badword2', 'offensive']
    for word in offensive_words:
        if word.lower() in username.lower():
            return False, "Username contains offensive language"
    return True, ""

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # Method to set password (hashed)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check if the entered password is correct
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Define Item model
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200))

# Create tables
with app.app_context():
    db.create_all()

# Error handling for 404 and 500
@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error="Resource not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify(error="An internal server error occurred"), 500

# User Registration Resource
class UserRegistration(Resource):
    @limiter.limit("5 per minute")  # Limit to 5 requests per minute to prevent abuse
    def post(self):
        data = request.get_json()

        # Input validation
        try:
            user_schema.load(data)
        except ValidationError as err:
            return jsonify(err.messages), 400

        username = data.get('username')
        password = data.get('password')

        # Censor usernames for offensive language
        valid, msg = censor_username(username)
        if not valid:
            return jsonify(message=msg), 400

        # Password complexity validation
        valid, msg = validate_password(password)
        if not valid:
            return jsonify(message=msg), 400

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify(message="Username already exists"), 400

        # Create new user and hash password
        new_user = User(username=username)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            logging.info(f'User {username} registered successfully.')
            return jsonify(message="User Registration Successful"), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify(message="Failed to register user due to an integrity error!"), 500

# User Login Resource
class UserLogin(Resource):
    @limiter.limit("5 per minute")  # Limit to 5 requests per minute to prevent brute force attacks
    def post(self):
        data = request.get_json()

        # Input validation
        try:
            user_schema.load(data)
        except ValidationError as err:
            return jsonify(err.messages), 400

        username = data.get('username')
        password = data.get('password')

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user and user.check_password(password):
            access_token = create_access_token(identity=user.username)  # Create JWT token
            logging.info(f'User {username} logged in successfully.')
            return jsonify(access_token=access_token), 200
        else:
            logging.warning(f'Failed login attempt for user {username}.')
            return jsonify(message="Invalid Credentials"), 401

# Item Resource (CRUD Operations)
class ItemResource(Resource):
    @jwt_required()
    def get(self, item_id):
        item = Item.query.get_or_404(item_id)
        return jsonify(id=item.id, name=item.name, description=item.description)

    @jwt_required()
    def put(self, item_id):
        data = request.get_json()

        # Input validation
        try:
            item_schema.load(data)
        except ValidationError as err:
            return jsonify(err.messages), 400

        item = Item.query.get_or_404(item_id)
        item.name = data.get('name')
        item.description = data.get('description')
        db.session.commit()
        return jsonify(message="Item Updated Successfully")

    @jwt_required()
    def delete(self, item_id):
        item = Item.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        return jsonify(message="Item Deleted Successfully")

# Item List Resource (GET all and POST new item)
class ItemListResource(Resource):
    @jwt_required()
    def get(self):
        items = Item.query.all()
        return jsonify(items=[{'id': item.id, 'name': item.name, 'description': item.description} for item in items])

    @jwt_required()
    def post(self):
        data = request.get_json()

        # Input validation
        try:
            item_schema.load(data)
        except ValidationError as err:
            return jsonify(err.messages), 400

        new_item = Item(name=data.get('name'), description=data.get('description'))
        db.session.add(new_item)
        db.session.commit()
        return jsonify(message="Item Created Successfully")

# Add resources to the API
api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(ItemResource, '/items/<int:item_id>')
api.add_resource(ItemListResource, '/items')

# Run the app in debug mode
if __name__ == '__main__':
    app.run(debug=True)
