from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from ragModel import initialize, run_query

app = Flask(_name_)
CORS(app)  # This will enable CORS for all routes

# Initialize the model and QA system
initialize()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/query', methods=['POST'])
def query():
    if request.is_json:
        user_query = request.json.get('query')
    else:
        user_query = request.form.get('query')

    if not user_query:
        return jsonify({'error': 'Missing query parameter'}), 400

    response = run_query(user_query)
    return jsonify({'response': response})

if _name_ == '_main_':
    app.run(debug=True)