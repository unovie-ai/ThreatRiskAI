import os
import logging
import subprocess
from flask import Flask, request, jsonify
from flasgger import Swagger
from flasgger.utils import swag_from
from werkzeug.utils import secure_filename
import config
from models import UploadRequestSchema, QueryRequestSchema, QueryResponseSchema, ErrorResponseSchema
from marshmallow import ValidationError

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(config)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Swagger configuration
swagger_config = {
    "headers": [
    ],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/"
}

swagger = Swagger(app, config=swagger_config)

# Utility function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# API endpoint for file upload
@app.route('/upload', methods=['POST'])
@swag_from({
    'summary': 'Upload a threat data file for processing',
    'consumes': ['multipart/form-data'],
    'parameters': [
        {
            'name': 'data_type',
            'in': 'formData',
            'type': 'string',
            'required': 'true',
            'enum': ['CVE', 'MITRE'],
            'description': 'Type of data (CVE or MITRE)'
        },
        {
            'name': 'platform',
            'in': 'formData',
            'type': 'string',
            'required': 'true',
            'description': 'Target platform (e.g., containers, Windows)'
        },
        {
            'name': 'file',
            'in': 'formData',
            'type': 'file',
            'required': 'true',
            'description': 'JSON file containing threat data'
        }
    ],
    'responses': {
        '200': {'description': 'File uploaded and processing initiated successfully'},
        '400': {'description': 'Invalid request parameters or file format', 'schema': ErrorResponseSchema},
        '500': {'description': 'Internal server error', 'schema': ErrorResponseSchema}
    }
})
def upload_file():
    try:
        # Validate request using schema
        schema = UploadRequestSchema()
        try:
            form_data = schema.load(request.form)
        except ValidationError as err:
            return jsonify({'error': err.messages}), 400

        data_type = form_data['data_type']
        platform = form_data['platform']

        # Check if a file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request.'}), 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return jsonify({'error': 'No file selected.'}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            logging.info(f"File saved to: {file_path}")

            # Call main.py to process the uploaded file
            command = [
                "python",
                "main.py",
                file_path,
                data_type,
                platform
            ]
            logging.info(f"Executing: {' '.join(command)}")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logging.error(f"Error processing file: {stderr.decode()}")
                return jsonify({'error': f"File processing failed: {stderr.decode()}"}), 500

            logging.info(stdout.decode())
            return jsonify({'message': 'File uploaded and processing initiated successfully.'}), 200
        else:
            return jsonify({'error': 'Invalid file format. Allowed formats: json'}), 400

    except Exception as e:
        logging.exception("An error occurred during file upload and processing.")
        return jsonify({'error': str(e)}), 500

# API endpoint for querying the database
@app.route('/query', methods=['GET'])
@swag_from({
    'summary': 'Query the threat intelligence database',
    'parameters': [
        {
            'name': 'query',
            'in': 'query',
            'required': 'true',
            'type': 'string',
            'description': 'The query string to search the database'
        }
    ],
    'responses': {
        '200': {'description': 'Successful query', 'schema': QueryResponseSchema},
        '400': {'description': 'Query parameter is missing', 'schema': ErrorResponseSchema},
        '500': {'description': 'Internal server error', 'schema': ErrorResponseSchema}
    }
})
def query_database():
    try:
        # Validate request using schema
        schema = QueryRequestSchema()
        try:
            query_data = schema.load(request.args)
        except ValidationError as err:
            return jsonify({'error': err.messages}), 400

        query = query_data['query']

        # Call scripts/query_databases.py to retrieve results
        command = [
            "python",
            "scripts/query_databases.py",
            query
        ]
        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error(f"Error querying database: {stderr.decode()}")
            return jsonify({'error': f"Database query failed: {stderr.decode()}"}), 500

        response = stdout.decode().strip()
        return jsonify({'result': response}), 200

    except Exception as e:
        logging.exception("An error occurred during the database query.")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
