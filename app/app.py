import os
import logging
import subprocess
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
import config
from models import QueryRequestSchema, QueryResponseSchema, ErrorResponseSchema
# from marshmallow import ValidationError

# Initialize FastAPI application
app = FastAPI(
    title="Threat Intelligence API",
    description="API for uploading threat data and querying the threat intelligence database",
    version="1.0.0"
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Request/Response Models
class UploadQuery(BaseModel):
    data_type: str = Field(..., description="Type of data (CVE or MITRE)")
    platform: str = Field(..., description="Target platform (e.g., containers, Windows)")

class EmbedJSON(BaseModel):
    data_type: str = Field(..., description="Type of data (CVE or MITRE)")
    platform: str = Field(..., description="Target platform")
    kg_directory: str = Field(..., description="Directory containing the knowledge graph CSV files")

class QueryParams(BaseModel):
    query: str = Field(..., description="The query string to search the database")

class MessageResponse(BaseModel):
    message: str

class ErrorResponse(BaseModel):
    error: str

# Utility function to check if the file extension is allowed
def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

@app.post(
    "/upload",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    },
    tags=["Upload"],
    summary="Upload a threat data file for processing"
)
async def upload_file(
    data_type: str = Form(..., description="Type of data (CVE or MITRE)"),
    platform: str = Form(..., description="Target platform (e.g., containers, Windows)"),
    file: UploadFile = File(..., description="The JSON file to upload")
):
    """
    Upload a threat data file for processing
    """
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected")

        if not allowed_file(file.filename):
            raise HTTPException(status_code=400, detail="Invalid file format. Allowed formats are json")

        # Save the file
        file_path = os.path.join(config.UPLOAD_FOLDER, file.filename)
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        logging.info(f"File saved to: {file_path}")

        command = [
            "python",
            "main.py",               
            data_type.upper(),
            platform,
            file_path,
            '-v'
        ]
        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode()
            logging.error(f"Error processing file: {error_msg}")
            raise HTTPException(status_code=500, detail=f"File processing failed: {error_msg}")

        logging.info(stdout.decode())
        return {"message": "File uploaded and processing initiated successfully."}

    except HTTPException as e:
        raise e
    except Exception as e:
        logging.exception("An error occurred during file upload and processing.")
        raise HTTPException(status_code=500, detail=str(e))

@app.post(
    "/embed",
    response_model=MessageResponse,
    responses={500: {"model": ErrorResponse}},
    tags=["Embed"],
    summary="Embed the knowledge graph into the database"
)
async def embed_knowledge_graph(body: EmbedJSON):
    """
    Embed the knowledge graph into the database
    """
    try:
        command = [
            "python",
            "main.py",
            "--embed",
            body.data_type.upper(),
            body.platform,
            "--kg-directory", body.kg_directory,
            "-v"
        ]
        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode()
            logging.error(f"Error embedding knowledge graph: {error_msg}")
            raise HTTPException(status_code=500, detail=f"Knowledge graph embedding failed: {error_msg}")

        logging.info(stdout.decode())
        return {"message": "Knowledge graph embedded successfully."}

    except HTTPException as e:
        raise e
    except Exception as e:
        logging.exception("An error occurred during knowledge graph embedding.")
        raise HTTPException(status_code=500, detail=str(e))

@app.get(
    "/query",
    response_model=Dict[str, str],
    responses={500: {"model": ErrorResponse}},
    tags=["Query"],
    summary="Query the threat intelligence database"
)
async def query_database(query: str):
    """
    Query the threat intelligence database
    """
    try:
        command = [
            "python",
            "inference/query_databases.py",
            query
        ]
        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode()
            logging.error(f"Error querying database: {error_msg}")
            raise HTTPException(status_code=500, detail=f"Database query failed: {error_msg}")

        response = stdout.decode().strip()
        return {"result": response}

    except HTTPException as e:
        raise e
    except Exception as e:
        logging.exception("An error occurred during the database query.")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
