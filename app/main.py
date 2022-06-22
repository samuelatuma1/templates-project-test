from flask import Flask, request, jsonify, Response
app = Flask(__name__)
app.config['SALT'] =  b'easy' 
app.config["SECRET_KEY"] = 'somesecretkey'

import json
# Hash Password

import hashlib

# 
# Middle ware Import 
# from middlewares.token_middleware import check_for_token


# Connect to database
import pymongo
try:
    
    
    mongo = pymongo.MongoClient("mongodb+srv://atuma:mystrongpassword@cluster0.k7wdg.mongodb.net/?retryWrites=true&w=majority", serverSelectionTimeoutMS=45000)
    db = mongo.templates
    mongo.server_info() # Trigger exception if we cannot connect
    print("Connected")
    
except Exception as err:
    print("#########################")
    print(err)
    print("#########################")

#############################################################################
@app.route("/", methods=['GET'])
def index():
    return "Hello world!!!!!"
@app.route("/register", methods = ['GET', "POST"])
def create_user():
    try:
        if request.method == 'POST':
            
            # get post data
            new_user = request.get_json(force = True)
            # Ensure all necessary fields are available
            valid_fields = ['first_name', 'last_name', 'email', 'password']
            for field in valid_fields:
                if field not in new_user.keys():
                    return jsonify({'error' : f'{field} is required'}), 400
            
            # Store data
            # Ensure Unique Emails
            
            if db.users.find_one({'email': new_user['email'] }):
                return jsonify({'error' : f'{new_user["email"]} already in use'}), 400
            
            # Hash User Password
            password = new_user['password'].encode('utf-8')
            hashed_password = hashlib.pbkdf2_hmac('sha256', password, app.config['SALT'], 100000).hex()
            new_user['password'] = hashed_password
            
            # Add templates field
            new_user['templates'] = []
            # Store Data
            dbResponse = db.users.insert_one(new_user)
            id = dbResponse.inserted_id
            
            # Return user back with his/her id converted to string 
            new_user['_id'] = f"{id}"
            
            return Response(
                response = json.dumps(new_user),
                status = 201,
                mimetype = 'application/json'
            )
        else:
            return Response(
                response = json.dumps({
                    "msg": "Does not accept get method"}),
                status = 400,
                mimetype = 'application/json'
            )
        
    except Exception as err:
        print(err)
        return jsonify({'error' : 'An error occured'}), 400



#################################################################
from functools import wraps
import jwt
from flask import jsonify, request

def check_for_token(func):
    global app
    @wraps(func)
    def wrapped(*args, **kwargs):
        auth = request.headers['authorization']
        if not auth:
            return jsonify({"message" : "Missing token"}), 403
        
        token = auth.split(' ')[1]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            setattr(request, 'data', data)
        except:
            return jsonify({"message": "Invalid token"}), 403
        return func(*args, **kwargs)
    return wrapped

#################################################################



import datetime
from bson.objectid import ObjectId

def create_token (id):
    token = jwt.encode({ 'id' : id, 'exp': datetime.datetime.now() + datetime.timedelta(seconds=600)}, app.config['SECRET_KEY'], algorithm='HS256')
    return token
@app.route("/login", methods=['POST'])
def login():
    if request.method == 'POST':
        # Get data
        form_data = request.get_json(force = True)
        
        # Check for user
        curr_user = db.users.find_one({'email': form_data['email']})
        if not curr_user:
            return (jsonify({
                'error': f"user with email {form_data['email']} does not exist"
            }), 400)
        
        # Check Password matches
        # Hash Password 
        password = form_data['password'].encode('utf-8')
        hashed_form_password = hashlib.pbkdf2_hmac('sha256', password, app.config['SALT'], 100000).hex()

        if curr_user['password'] != hashed_form_password:
            return (jsonify({
                'error': f"Please, sign in with the correct password"
            }), 400)
        curr_user['_id'] = f'{curr_user["_id"]}'
        
        # Encode _id
        curr_user['token'] = create_token(curr_user['_id'])
        print('found', db.users.find_one({'_id': ObjectId(curr_user['_id'] )}))
        
        return curr_user
        

@app.route('/private', methods=['GET'])
@check_for_token
def private():
    return 'Authorized'

# Templates
import copy
@app.route("/template", methods=['GET', 'POST'])
@check_for_token
def template():
    signed_in_user = db.users.find_one({"_id": ObjectId(request.data['id'])})
    
    if request.method == 'POST':
        # return request.data
        form_data = request.get_json()
        
        # Get user with id
        # Check if template contains all necessary data
        valid_fields = ['template_name','subject','body']
        for field in valid_fields:
            if field not in form_data.keys():
                return jsonify({'error' : f'{field} is required'}), 400
        
        # create template for user
        new_template = form_data
        new_template['user'] = request.data['id']
        new_template = db.template.insert_one(new_template)
        user_templates = signed_in_user['templates']
        user_templates.append(f"{new_template.inserted_id}")
        
        db.users.update_one({"_id": ObjectId(request.data['id'])}, {"$set": {"templates": user_templates}})
        form_data['_id'] = f'{new_template.inserted_id}'
        
        return jsonify(form_data)
    
    all_templates = []
    for id in signed_in_user['templates']:
        find_template = copy.deepcopy(db.template.find_one({"_id": ObjectId(id)}))
        find_template['_id'] = f'{find_template["_id"]}'
        all_templates.append(find_template)
        
    return jsonify({"all_templates": all_templates})
        

@app.route("/template/<string:template_id>", methods=['DELETE', 'PUT'])
@check_for_token
def template_update(template_id):
    signed_in_user = db.users.find_one({"_id": ObjectId(request.data['id'])})
    # Check if template exists for User
    valid_templates = signed_in_user['templates']
    
    if template_id not in valid_templates:
        return jsonify({"error": "Template not found"}), 400
    if request.method == 'DELETE':
        
        # If template exists
        # Delete from templates
        deleted = db.template.delete_one({'id' : ObjectId(template_id)})
        
        # Remove relationship from user
        print(deleted)
        valid_templates.remove(template_id)
        
        db.users.update_one({"_id": ObjectId(request.data['id'])}, {"$set": {"templates": valid_templates}})
        return jsonify({
            "id": template_id,
            "delete_count" : 1
        }), 204
        
    if request.method == 'PUT':
        
        data_to_update = request.get_json(force = True)
        updated = db.template.update_one({'_id': ObjectId(template_id)}, {"$set": data_to_update})
        
        updated_data = db.template.find_one({'_id': ObjectId(template_id)}, {'_id': 0})
        return jsonify(updated_data)
        
        
        
        
        

    
    
    
    
        
##############################################################
