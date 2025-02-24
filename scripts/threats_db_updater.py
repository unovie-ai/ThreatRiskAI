import argparse
import logging
import os
import subprocess
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DB_DIR = "db"
EMBEDDING_MODEL = "jina-embeddings-v2-small-en"
DB_FILE = "threats.db"
COLLECTION_NAME = "threats"

def update_threats_database(csv_file_path, data_type):
    """
    Creates or updates a threats database and embeds the knowledge graph data.

    Args:
        csv_file_path (str): The path to the knowledge graph CSV file.
        data_type (str): The type of data (e.g., cve or mitre).
    """
    db_path = os.path.join(DB_DIR, DB_FILE)

    # Create database directory if it doesn't exist
    os.makedirs(DB_DIR, exist_ok=True)

    # Check if the database exists
    db_exists = os.path.exists(db_path)

    llm_command = [
        "llm", "embed-multi", COLLECTION_NAME,
        "-m", EMBEDDING_MODEL,
        "-d", db_path,
        "--files", ".", csv_file_path,
        "--store"
    ]

    # Check if the collection already exists
    collection_exists = False
    if db_exists:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (COLLECTION_NAME,))
            result = cursor.fetchone()
            if result:
                collection_exists = True
            conn.close()
        except sqlite3.Error as e:
            logging.error(f"Error checking for collection: {e}")
            return

    if not db_exists:
        logging.info(f"Creating database: {db_path}")
    elif collection_exists:
        logging.info(f"Collection '{COLLECTION_NAME}' already exists in {db_path}. Skipping embedding.")
        return
    else:
        logging.info(f"Updating database: {db_path} with collection '{COLLECTION_NAME}'")

    try:
        # Execute the llm command
        logging.info(f"Executing command: {' '.join(llm_command)}")
        subprocess.run(llm_command, check=True)
        logging.info(f"Successfully updated {db_path} with data for collection '{COLLECTION_NAME}'.")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing llm command: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def main():
    """
    Main function to parse arguments and call the database update function.
    """
    parser = argparse.ArgumentParser(description="Create or update a threats database and embed knowledge graph data.")
    parser.add_argument("csv_file_path", help="Path to the knowledge graph CSV file")
    parser.add_argument("data_type", help="Type of data (cve or mitre)")
    args = parser.parse_args()

    update_threats_database(args.csv_file_path, args.data_type)


if __name__ == "__main__":
    main()
