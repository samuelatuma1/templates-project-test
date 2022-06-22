import json
import random
def verify_fields(fields: list, document) -> bool:
    for field in fields:
        if field not in document:
            return False
    return True
def gen_id():
    chars = '1234567890abcdefghijklmnopqrstuvwxyz'
    _id = ''
    for i in range(25):
        _id += random.choice(chars)
    return _id
class user:
    def __init__(self, file_path: str, fields: list = []):
        self.path = file_path
        self.fields = fields
    def insert_one(self, document: dict):
        if type(document) != dict:
            return {"error": "invalid document"}
        with open(self.path, 'r') as file:
            # Read file from json
            read = json.load(file)
            
            # verify fields
            fields = self.fields
            if verify_fields(fields, document):
                # Generate random_id
                document['_id'] = gen_id()
                
                # Add document to read and update file
                read.append(document)
                
                print(read)
                with open(self.path, "w") as outfile:
                    json.dump(read, outfile)
                
            else:
                return {"error": "invalid document"}
        
    def find_one(self, document: dict):
        with open(self.path, 'r') as file:
            # Read file from json
            read = json.load(file)

User = user('user.json')
print(User.insert_one({
    'first_name': "sam", "last_name": "pete",
    "email": "email3",
    "password": "12345"
    }))