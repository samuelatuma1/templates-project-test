from flask import Flask
app = Flask(__name__)

@app.route("/", methods=['GET', 'POST'])
def index():
    return "<h1>You am very good at JavaScript</h1>"
