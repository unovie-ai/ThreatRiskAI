import argparse
import logging
import os
import subprocess
import dotenv
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
dotenv.load_dotenv()

# Constants from environment variables
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.0-flash-exp")  # Default model if not in .env
NUM_RESULTS = int(os.getenv("NUM_RESULTS", "10"))  # Default number of results if not in .env

def extract_subject(query):
    """
    Extracts the subject from the query using an LLM.

    Args:
        query (str): The user's query.

    Returns:
        str: The extracted subject, or None if extraction fails.
    """
    try:
        command = [
            "llm", "-m", LLM_MODEL,
            f"\"Extract subject from the following: {query}\""
        ]
        logging.info(f"Executing command: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error(f"Error extracting subject: {stderr.decode()}")
            return None

        subject = stdout.decode().strip().split('\n')[0]  # Take the first line
        # Consider the first item inside ** **
        if "**" in subject:
            subject = subject.split("**")[1]
        logging.info(f"Extracted subject: {subject}")
        return subject

    except FileNotFoundError:
        logging.error("llm command not found. Ensure it is installed and in your PATH.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def query_database(db_path, collection, subject):
    """
    Queries a specific database and collection for similar content.

    Args:
        db_path (str): The path to the SQLite database file.
        collection (str): The name of the collection to query.
        subject (str): The subject to search for.

    Returns:
        str: The concatenated results from the database query, or None if an error occurs.
    """
    try:
        command = [
            "llm", "similar", collection,
            "-n", str(NUM_RESULTS),
            "-d", db_path,
            "-c", f"\"{subject}\""
        ]
        logging.info(f"Executing command: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.warning(f"Error querying {db_path}/{collection}: {stderr.decode()}")
            return None

        results = stdout.decode().strip()
        logging.info(f"Query results from {db_path}/{collection}:\n{results}")
        return results

    except FileNotFoundError:
        logging.error("llm command not found. Ensure it is installed and in your PATH.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def generate_final_response(query, context):
    """
    Generates the final LLM-processed response using the provided context.

    Args:
        query (str): The original user query.
        context (str): The concatenated results from the database queries.

    Returns:
        str: The final LLM-processed response, or None if generation fails.
    """
    try:
        command = [
            "llm", "-m", LLM_MODEL
        ]
        input_text = f"{query}\nContext:\n{context}"
        logging.info(f"Executing command: {' '.join(command)}")
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=input_text.encode('utf-8'))

        if process.returncode != 0:
            logging.error(f"Error generating final response: {stderr.decode()}")
            return None

        response = stdout.decode().strip()
        logging.info(f"Final LLM response:\n{response}")
        return response

    except FileNotFoundError:
        logging.error("llm command not found. Ensure it is installed and in your PATH.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def main():
    """
    Main function to orchestrate the database querying and response generation process.
    """
    parser = argparse.ArgumentParser(description="Query multiple databases and collections to generate a final LLM response.")
    parser.add_argument("query", help="The user's query.")
    args = parser.parse_args()

    # Database and collection configurations from .env
    databases_str = os.getenv("DATABASES", "db/cve.db:containers,db/mitre.db:windows")
    databases = {}
    for db_collection in databases_str.split(','):
        try:
            db_path, collection = db_collection.split(':')
            if db_path not in databases:
                databases[db_path] = []
            databases[db_path].append(collection)
        except ValueError:
            logging.warning(f"Invalid database:collection format: {db_collection}. Skipping.")
            continue

    # 1. Extract the subject from the query
    subject = extract_subject(args.query)
    if not subject:
        logging.error("Failed to extract subject from the query.")
        return

    # 2. Query each database and collection
    aggregated_results = ""
    for db_path, collections in databases.items():
        if not os.path.exists(db_path):
            logging.warning(f"Database not found: {db_path}")
            continue

        for collection in collections:
            results = query_database(db_path, collection, subject)
            if results:
                aggregated_results += f"\n-- Results from {db_path}/{collection}:\n{results}"

    # 3. Generate the final LLM-processed response
    if not aggregated_results:
        logging.info("No results found in any database. Returning a default response.")
        final_response = "No relevant information found in the databases."
    else:
        final_response = generate_final_response(args.query, aggregated_results)
        if not final_response:
            logging.error("Failed to generate final response.")
            return

    print(final_response)

if __name__ == "__main__":
    main()
