import argparse
import logging
import os
import subprocess
import sqlite3
import csv
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DB_DIR = "db"
EMBEDDING_MODEL = "jina-embeddings-v2-small-en"

def update_database_row_by_row(csv_file_path, data_type, platform):
    """
    Creates or updates a CVE or MITRE database and embeds the knowledge graph data row by row.

    Args:
        csv_file_path (str): The path to the knowledge graph CSV file.
        data_type (str): The type of data ("CVE" or "MITRE").
        platform (str): The platform (e.g., "containers", "Windows", "Linux"), used as collection name.
    """
    db_file = f"{data_type.lower()}.db"
    db_path = os.path.join(DB_DIR, db_file)

    # Create database directory if it doesn't exist
    os.makedirs(DB_DIR, exist_ok=True)

    # Check if the database exists
    db_exists = os.path.exists(db_path)

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

    start_time = time.time()
    row_count = 0
    success_count = 0
    failure_count = 0

    try:
        with open(csv_file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                row_count += 1
                row_start_time = time.time()
                row_id = row.get('id', f"row-{row_count}")  # Assuming 'id' is a column in the CSV
                content = "\\n".join(row.values())  # Concatenate all values in the row

                # Determine the llm command based on data type
                object_id = row_id
                object_content = content

                llm_command = [
                    "llm",
                    "embed",
                    platform,
                    str(object_id),
                    "-m",
                    EMBEDDING_MODEL,
                    "-d",
                    db_path,
                    "-c",
                    object_content,
                    "--store"
                ]

                try:
                    # Check if the embedding already exists
                    check_command = [
                        "llm",
                        "search",
                        platform,
                        "--id",
                        str(object_id),
                        "-d",
                        db_path
                    ]
                    result = subprocess.run(check_command, text=True, capture_output=True)
                    if "No results found" not in result.stdout:
                        logging.warning(f"Embedding already exists for ID: {object_id} in collection: {platform}. Skipping.")
                        continue

                    # Execute the llm command
                    logging.info(f"Executing command: {' '.join(llm_command)}")
                    subprocess.run(llm_command, text=True, check=True)
                    success_count += 1
                    row_end_time = time.time()
                    logging.info(f"Successfully embedded row {row_count} (ID: {row_id}) in {row_end_time - row_start_time:.2f} seconds.")

                except subprocess.CalledProcessError as e:
                    logging.error(f"Error executing llm command for row {row_count} (ID: {row_id}): {e}")
                    failure_count += 1
                except Exception as e:
                    logging.error(f"An unexpected error occurred for row {row_count} (ID: {row_id}): {e}")
                    failure_count += 1

    except FileNotFoundError:
        logging.error(f"CSV file not found: {csv_file_path}")
        return
    except csv.Error as e:
        logging.error(f"CSV error: {e}")
        return
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return

    end_time = time.time()
    total_time = end_time - start_time

    logging.info(f"Total rows processed: {row_count}")
    logging.info(f"Successful embeddings: {success_count}")
    logging.info(f"Failed embeddings: {failure_count}")
    logging.info(f"Total time taken: {total_time:.2f} seconds")
    logging.info(f"Average time per row: {total_time / row_count:.2f} seconds")


def main():
    """
    Main function to parse arguments and call the database update function.
    """
    parser = argparse.ArgumentParser(description="Create or update a CVE or MITRE database and embed knowledge graph data row by row.")
    parser.add_argument("csv_file_path", help="Path to the knowledge graph CSV file")
    parser.add_argument("data_type", help="Type of data (CVE or MITRE)")
    parser.add_argument("platform", help="Platform (e.g., containers, Windows, Linux)")
    args = parser.parse_args()

    update_database_row_by_row(args.csv_file_path, args.data_type, args.platform)


if __name__ == "__main__":
    main()

