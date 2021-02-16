"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User
#from models import Person
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
# Setup the Flask-JWT-Simple extension
app.config['JWT_SECRET_KEY'] = 'lgs%(@j(za@<2&BG|(V{Q}9VY5MIH,{kN26;:Tu;+ps-U9 R46w]6|mh}&[AK_w-'  # Change this!
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)
jwt = JWTManager(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

# Provide a method to create access tokens. The create_jwt()
# function is used to actually generate the token
@app.route('/login', methods=['POST'])
def login():
    # make sure request is a json
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    # get email and password from request
    email = request.json.get('email', None)
    password = request.json.get('password', None)

    # if params are empty, return a 400
    if not email:
        return jsonify({"msg": "Missing email parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    # try to find user
    try:
        # query user
        user = User.query.filter_by(email=email).first()
        # test validate method. 
        if user.validate(password):
            # if user is validated (password is correct), return the token
            response_msg = {'jwt': create_access_token(identity=email)}
            status_code = 200
        else:
            # otherwise, raise an exception so that they check their email and password
            raise Exception('Failed to login. Check your email and password.')
    # catch the specific exception and store in var
    except Exception as e:
        # format a json respons with the exception
        response_msg = {
            'msg': str(e),
            'status': 401
        }
        status_code = 401
    
    # general return in json with status
    return jsonify(response_msg), status_code

# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
