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



def main():
    """
    Main function to orchestrate the database querying and response generation process.
    """
    parser = argparse.ArgumentParser(description="Query a database and generate a final LLM response.")
    parser.add_argument("query", help="The user's query.")
    args = parser.parse_args()

    try:
        # Construct the llm similar command
        similar_command = [
            "llm", "similar", "threats",
            "-n", str(NUM_RESULTS),
            "-d", "db/threats.db",
            "-c", f"\"{args.query}\""
        ]

        subject = extract_subject(args.query)

        # Construct the final llm command
        final_command = [
            "llm", "-m", LLM_MODEL,
            f"\"{subject}\""
        ]

        logging.info(f"Executing command: {' '.join(similar_command)} | {' '.join(final_command)}")

        # Execute the llm similar command and pipe its output to the final llm command
        similar_process = subprocess.Popen(similar_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        final_process = subprocess.Popen(final_command, stdin=similar_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Capture the output from the final llm command
        stdout, stderr = final_process.communicate()

        if final_process.returncode != 0:
            logging.error(f"Error generating final response: {stderr.decode()}")
            return

        response = stdout.decode().strip()
        logging.info(f"Final LLM response:\n{response}")
        print(response)

    except FileNotFoundError:
        logging.error("llm command not found. Ensure it is installed and in your PATH.")
        return
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return

if __name__ == "__main__":
    main()
