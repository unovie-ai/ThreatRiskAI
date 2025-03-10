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

        # Construct the llm similar command
        similar_commands = []
        for db_path, collection_name in db_collection_pairs:
            similar_command = [
                "llm", "similar", collection_name,
                "-n", str(NUM_RESULTS),
                "-d", db_path,
                "-c", subject
            ]
            similar_commands.append(similar_command)

        # Construct the final llm command
        final_command = [
            "llm", "-m", LLM_MODEL,
            f"\"{args.query}\""
        ]

        # Execute the similar commands and pipe the output to the final command
        all_stdout = []
        for command in similar_commands:
            logging.info(f"Executing similar command: {' '.join(command)}")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logging.error(f"Error querying database: {stderr.decode()}")
                continue

            # Strip whitespace from the output and append
            all_stdout.append(stdout.strip())

        # Pipe the output of all similar commands to the final command
        if all_stdout:
            # Concatenate all stdout with a more descriptive delimiter
            delimiter = b"\n---\n"
            input_data = delimiter.join(all_stdout)

            final_command_str = ' '.join(final_command)
            logging.info(f"Executing final command: {final_command_str}")
            final_process = subprocess.Popen(final_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = final_process.communicate(input=input_data)
        else:
            stdout = b""
            stderr = b"No data from similar commands"
            final_process = type('obj', (object,), {'returncode': 1})()

        if final_process.returncode != 0:
            logging.error(f"Error generating final response: {stderr.decode()}")
            if stderr:
                logging.error(f"Error generating final response: {stderr.decode()}")
            return None

        response = stdout.decode().strip()
        print(response)
        return response

    except FileNotFoundError:
        logging.error("llm command not found. Ensure it is installed and in your PATH.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

if __name__ == "__main__":
    main()
