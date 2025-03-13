import os
import logging
import subprocess
from flask import Flask, request, jsonify
from flasgger import Swagger
from flasgger.utils import swag_from
from werkzeug.utils import secure_filename
import config
from models import QueryRequestSchema, QueryResponseSchema, ErrorResponseSchema
from marshmallow import ValidationError

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(config)
app.config['TRAP_HTTP_EXCEPTIONS'] = True

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Swagger configuration
swagger_config = {
    "openapi": "3.0.0",
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
            'required': True,
            'enum': ['CVE', 'MITRE'],
            'description': 'Type of data (CVE or MITRE)'
        },
        {
            'name': 'platform',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'Target platform (e.g., containers, Windows)'
        },
        {
            'name': 'file',
            'in': 'formData',
            'type': 'file',
            'required': True,
            'description': 'The JSON file to upload'
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
        # Check if the request has the data_type, platform and file part
        if 'data_type' not in request.form or 'platform' not in request.form or 'file' not in request.files:
            return jsonify({'error': 'Missing data_type, platform or file'}), 400

        data_type = request.form['data_type']
        platform = request.form['platform']
        file = request.files['file']

        # Check if the file is one of the allowed types/extensions
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
                data_type.upper(),
                platform,
                '-v'
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
            return jsonify({'error': 'Invalid file format. Allowed formats are json'}), 400

    except Exception as e:
        logging.exception("An error occurred during file upload and processing.")
        return jsonify({'error': str(e)}), 500

# API endpoint for embedding the knowledge graph
@app.route('/embed', methods=['POST'])
@swag_from({
    'summary': 'Embed the knowledge graph into the database',
    'consumes': ['application/json'],
    'parameters': [
        {
            'name': 'data_type',
            'in': 'json',
            'type': 'string',
            'required': True,
            'enum': ['CVE', 'MITRE'],
            'description': 'Type of data (CVE or MITRE)'
        },
        {
            'name': 'platform',
            'in': 'json',
            'type': 'string',
            'required': True,
            'description': 'Target platform (e.g., containers, Windows)'
        },
        {
            'name': 'kg_directory',
            'in': 'json',
            'type': 'string',
            'required': True,
            'description': 'Directory containing the knowledge graph CSV files'
        }
    ],
    'responses': {
        '200': {'description': 'Knowledge graph embedded successfully'},
        '400': {'description': 'Invalid request parameters', 'schema': ErrorResponseSchema},
        '500': {'description': 'Internal server error', 'schema': ErrorResponseSchema}
    }
})
def embed_knowledge_graph():
    try:
        data = request.get_json()
        data_type = data.get('data_type')
        platform = data.get('platform')
        kg_directory = data.get('kg_directory')

        if not all([data_type, platform, kg_directory]):
            return jsonify({'error': 'Missing data_type, platform, or kg_directory'}), 400

        # Call main.py with the embed option
        command = [
            "python",
            "main.py",
            "--embed",
             data_type.upper(),
             platform,
            "--kg-directory", kg_directory,
            "-v"
        ]
        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error(f"Error embedding knowledge graph: {stderr.decode()}")
            return jsonify({'error': f"Knowledge graph embedding failed: {stderr.decode()}"}), 500

        logging.info(stdout.decode())
        return jsonify({'message': 'Knowledge graph embedded successfully.'}), 200

    except Exception as e:
        logging.exception("An error occurred during knowledge graph embedding.")
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
            "inference/query_databases.py",
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
    app.run(debug=True, host="0.0.0.0", port=8000)
