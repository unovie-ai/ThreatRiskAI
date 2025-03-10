import argparse
import logging
import os
import subprocess
import sqlite3
import configparser

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DB_DIR = "db"

def update_database(data_type, platform, kg_directory):
    """
    Creates or updates a CVE or MITRE database and embeds the knowledge graph data.

    Args:
        data_type (str): The type of data ("CVE" or "MITRE").
        platform (str): The platform (e.g., "containers", "Windows", "Linux"), used as collection name.
        kg_directory (str): The directory containing the knowledge graph CSV files.
    """
    db_file = f"{data_type.lower()}.db"
    db_path = os.path.join(DB_DIR, db_file)

    # Read configuration from config.ini
    config = configparser.ConfigParser()
    config.read('config.ini')
    embedding_model = config.get('llm', 'embedding_model', fallback='jina-embeddings-v2-small-en')

    # Create database directory if it doesn't exist
    os.makedirs(DB_DIR, exist_ok=True)

   # Check if the database exists
    db_exists = os.path.exists(db_path)

    # Determine the llm command based on data type
    llm_command = [
        "llm", "embed-multi", platform,
        "-m", embedding_model,
        "-d", db_path,
        "--files", kg_directory.rstrip('/'),
        "**/*.csv",
        "--store"
    ]

    # Check if the collection already exists
    collection_exists = False
    if db_exists:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (platform,))
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
        logging.info(f"Collection '{platform}' already exists in {db_path}. Skipping embedding.")
        return
    else:
        logging.info(f"Updating database: {db_path} with collection '{platform}'")

    try:
        # Execute the llm command
        logging.info(f"Executing command: {' '.join(llm_command)}")
        subprocess.run(llm_command, check=True, shell=False)
        logging.info(f"Successfully updated {db_path} with {data_type} data for platform '{platform}'.")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing llm command: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def main():
    """
    Main function to parse arguments and call the database update function.
    """
    parser = argparse.ArgumentParser(description="Create or update a CVE or MITRE database and embed knowledge graph data.")
    parser.add_argument("data_type", help="Type of data (CVE or MITRE)")
    parser.add_argument("platform", help="Platform (e.g., containers, Windows, Linux)")
    parser.add_argument("kg_directory", help="Directory containing the knowledge graph CSV files")
    args = parser.parse_args()

    update_database(args.data_type, args.platform, args.kg_directory)


if __name__ == "__main__":
    main()
