import argparse
import logging
import os
import subprocess
import json

# Constants for directory paths
OUTPUT_DIR = "output"

# Default logging level
DEFAULT_LOG_LEVEL = logging.INFO

def process_data(json_file_path, data_type, platform):
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
            logging.error(f"Error processing {data_type}  {stderr.decode()}")
            return None

        logging.info(stdout.decode())
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


def main():
    """
    Main function to orchestrate the data processing pipeline.
    """
    parser = argparse.ArgumentParser(description="Process threat data (MITRE or CVE) based on the specified platform.")
    parser.add_argument("json_file_path", help="Path to the input JSON file")
    parser.add_argument("data_type", help="Type of data (MITRE or CVE)")
    parser.add_argument("platform", help="Target platform (e.g., containers, Windows, Linux)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)")
    args = parser.parse_args()

    # Set logging level based on verbosity
    log_level = logging.DEBUG if args.verbose else DEFAULT_LOG_LEVEL
    logging.getLogger().setLevel(log_level)

    # Process the data
    processed_file_path = process_data(args.json_file_path, args.data_type, args.platform)

    if processed_file_path:
        logging.info(f"Processed data saved to: {processed_file_path}")
    else:
        logging.error("Data processing failed.")


if __name__ == "__main__":
    main()
