import argparse
import logging
import os
import subprocess
import dotenv
import sqlite3
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
dotenv.load_dotenv()

# Constants from environment variables
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.0-flash-exp")
NUM_RESULTS = int(os.getenv("NUM_RESULTS", "10"))
DATABASE_COLLECTIONS = os.getenv("DATABASES", "db/threats.db:threats")

def extract_subject(query):
    """Extracts the subject from the query using an LLM.

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
        # Consider the first item inside ""
        elif "\"" in subject:
            subject = subject.split("\"")[1]

        # Remove sentences like "The subject is", "The subjects are"
        subject = re.sub(r"^(The subject is|The subjects are)\s*:\s*", "", subject, flags=re.IGNORECASE)

        logging.info(f"Extracted subject: {subject}")
        return subject

    except FileNotFoundError:
        logging.error("llm command not found. Ensure it is installed and in your PATH.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def main():
    """Main function to orchestrate the database querying and response generation process."""
    parser = argparse.ArgumentParser(description="Query a database and generate a final LLM response.")
    parser.add_argument("query", help="The user's query.")
    args = parser.parse_args()

    try:
        subject = extract_subject(args.query)
        if not subject:
            logging.error("Failed to extract subject from query.")
            return None

        # Fetch database and collection pairs from environment variable
        db_collection_pairs = [pair.split(":") for pair in DATABASE_COLLECTIONS.split(",")]

        # Collect similar results from all databases
        similar_results = []
        for db_path, collection_name in db_collection_pairs:
            # Construct the llm similar command
            similar_command = [
                "llm", "similar", collection_name,
                "-n", str(NUM_RESULTS),
                "-d", db_path,
                "-c", f"\"{subject}\""
            ]

            logging.info(f"Executing command: {' '.join(similar_command)}")
            process = subprocess.Popen(similar_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logging.error(f"Error querying database {db_path}: {stderr.decode()}")
                continue

            similar_results.append(stdout.decode().strip())

        # Concatenate the results
        combined_results = "\\n".join(similar_results)

        # Construct the final llm command
        final_command = [
            "llm", "-m", LLM_MODEL,
            f"\"{args.query}\\nContext:\\n{combined_results}\""
        ]

        logging.info(f"Executing final command: {' '.join(final_command)}")
        final_process = subprocess.Popen(final_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = final_process.communicate()

        if final_process.returncode != 0:
            logging.error(f"Error generating final response: {stderr.decode()}")
            return None

        response = stdout.decode().strip()
        return response

    except FileNotFoundError:
        logging.error("llm command not found. Ensure it is installed and in your PATH.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

if __name__ == "__main__":
    response = main()
    if response:
        print(response)
