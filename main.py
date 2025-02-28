import argparse
import logging
import os
import subprocess
import json
import logging
import sys  # Import sys for exit codes

# Constants for directory paths
OUTPUT_DIR = "output"

# Default logging level
DEFAULT_LOG_LEVEL = logging.INFO

def process_data(json_file_path, data_type, platform, args):
    logging.debug(f"process_data called with: json_file_path={json_file_path}, data_type={data_type}, platform={platform}, args={args}")
    """
    Processes data based on the specified data type (MITRE or CVE).

    Args:
        json_file_path (str): Path to the input JSON file.
        data_type (str): Specifies whether the input file is "MITRE" or "CVE".
        platform (str): The target platform for filtering (e.g., "containers", "Windows", "Linux").

    Returns:
        str: The path to the processed JSON file, or None if an error occurred.
    """

    # Create the output directory if it doesn't exist
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # Extract filename from path
    file_name = os.path.basename(json_file_path)
    output_file_path = os.path.join(OUTPUT_DIR, file_name)

    try:
        if data_type.upper() == "MITRE":
            script_path = "scripts/mitre_processor.py"
        elif data_type.upper() == "CVE":
            script_path = "scripts/cve_processor.py"
        else:
            raise ValueError("Invalid data_type. Must be 'MITRE' or 'CVE'.")

        # Construct the command to execute the script
        command = [
            "python",
            script_path,
            json_file_path,
            platform,
            "--output_dir", OUTPUT_DIR
        ]

        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error(f"Error processing {data_type}: {stderr.decode()}")
            if args.verbose:
                logging.debug(f"STDOUT: {stdout.decode()}")
                logging.debug(f"STDERR: {stderr.decode()}")
            return None

        logging.info(stdout.decode())
        if args.verbose:
            logging.debug(f"STDOUT: {stdout.decode()}")
            logging.debug(f"STDERR: {stderr.decode()}")
        return output_file_path

    except ValueError as e:
        logging.error(str(e))
        return None
    except FileNotFoundError:
        logging.error(f"Script not found: {script_path}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        return None

def generate_knowledge_graph(json_file_path, data_type, args):
    logging.debug(f"generate_knowledge_graph called with: json_file_path={json_file_path}, data_type={data_type}, args={args}")
    """
    Generates a knowledge graph from the processed JSON file and returns the path to the generated CSV file.

    Args:
        json_file_path (str): Path to the processed JSON file.
        data_type (str): Type of data (MITRE or CVE).

    Returns:
        str: The path to the generated CSV file, or None if an error occurred.
    """
    try:
        # Extract filename from path
        file_name = os.path.splitext(os.path.basename(json_file_path))[0]
        csv_file_path = os.path.join("knowledge_graphs", f"{file_name}.csv")

        command = [
            "python",
            "scripts/knowledge_graph_generator.py",
            json_file_path,
            data_type.lower()
        ]

        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        process.wait() # Wait for the process to finish and get return code

        if process.returncode != 0: # Check return code instead of stdout/stderr
            logging.error(f"Knowledge graph generator failed with exit code: {process.returncode}")
            if args.verbose:
                logging.debug(f"STDOUT: {stdout.decode()}")
                logging.debug(f"STDERR: {stderr.decode()}")
            return None
        else:
            logging.info(stdout.decode())
            if args.verbose:
                logging.debug(f"STDOUT: {stdout.decode()}")
                logging.debug(f"STDERR: {stderr.decode()}")
            return csv_file_path

    except FileNotFoundError:
        logging.error("Script not found: scripts/knowledge_graph_generator.py")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        return None


def main():
    """
    Main function to orchestrate the data processing pipeline.
    """
    parser = argparse.ArgumentParser(description="Process threat data (MITRE or CVE) based on the specified platform.")
    parser.add_argument("data_type", help="Type of data (MITRE or CVE)", nargs='?')
    parser.add_argument("platform", help="Target platform (e.g., containers, Windows, Linux)", nargs='?')
    parser.add_argument("json_file_path", help="Path to the input JSON file", nargs='?')
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)")
    parser.add_argument("--skip-kg", action="store_true", help="Skip knowledge graph generation")
    parser.add_argument("--embed", action="store_true", help="Embed the knowledge graph into the database")
    parser.add_argument("--kg-directory", default="knowledge_graphs", help="Directory containing the knowledge graph CSV files")
    args = parser.parse_args()

    # Set logging level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.embed:
        if not (args.data_type and args.platform):
            parser.error("--embed requires data_type and platform to be specified")
            sys.exit(1)

        csv_file_path = os.path.join(args.kg_directory, f"{args.data_type.lower()}.csv")

        # Call db_updater.py to embed the knowledge graph into the database
        command = [
            "python",
            "scripts/db_updater.py",
            args.data_type,
            args.platform,
            args.kg_directory.rstrip('/')
        ]
        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error(f"Error updating database: {stderr.decode()}")
            if args.verbose:
                logging.debug(f"STDOUT: {stdout.decode()}")
                logging.debug(f"STDERR: {stderr.decode()}")
            sys.exit(1)
        else:
            logging.info(stdout.decode())
            if args.verbose:
                logging.debug(f"STDOUT: {stdout.decode()}")
                logging.debug(f"STDERR: {stderr.decode()}")

    else:
        if not (args.json_file_path and args.data_type and args.platform):
            parser.error("json_file_path, data_type and platform are required unless --embed is used")
            sys.exit(1)

        # Process the data
        processed_file_path = process_data(args.json_file_path, args.data_type.upper(), args.platform, args)

        if processed_file_path:
            logging.info(f"Processed data saved to: {processed_file_path}")

            csv_file_path = generate_knowledge_graph(processed_file_path, args.data_type, args)
            if not csv_file_path:
                logging.error("Knowledge graph generation failed.")
                sys.exit(1)  # Exit if KG generation fails
        else:
            logging.error("Data processing failed.")
            sys.exit(1)  # Exit if data processing fails


if __name__ == "__main__":
    main()
