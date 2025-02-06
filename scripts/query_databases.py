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
    """
    Main function to orchestrate the database querying and response generation process.
    """
    parser = argparse.ArgumentParser(description="Query a database and generate a final LLM response.")
    parser.add_argument("query", help="The user's query.")
    args = parser.parse_args()

    try:
        subject = extract_subject(args.query)

        # Construct the llm similar command
        similar_command = [
            "llm", "similar", "threats",
            "-n", str(NUM_RESULTS),
            "-d", "db/threats.db",
            "-c", f"\"{subject}\""
        ]

        # Construct the final llm command
        final_command = [
            "llm", "-m", LLM_MODEL,
            f"\"{args.query}\""
        ]

        logging.info(f"Executing command: {' '.join(similar_command)} | {' '.join(final_command)}")

        # Execute the llm similar command and pipe its output to the final llm command
        similar_process = subprocess.Popen(similar_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        final_process = subprocess.Popen(final_command, stdin=similar_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Capture the output from the final llm command
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
