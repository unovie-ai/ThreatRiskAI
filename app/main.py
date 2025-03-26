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
            script_path = "ingestion/mitre_processor.py"
            # For MITRE, use the existing approach
            command = [
                sys.executable,
                script_path,
                json_file_path,
                platform,
                "--output_dir", OUTPUT_DIR
            ]
        elif data_type.upper() == "CVE":
            # For CVE, use our new processor approach
            from ingestion.cve_processor import CVEProcessor
            processor = CVEProcessor()
            
            with open(json_file_path, 'r') as f:
                data = json.load(f)
            
            # Process the data
            processed_data = processor.process(data)
            
            # Save to CSV directly
            csv_file_path = os.path.join("knowledge_graphs", f"{os.path.splitext(file_name)[0]}.csv")
            os.makedirs("knowledge_graphs", exist_ok=True)
            
            with open(csv_file_path, 'w') as f:
                if processed_data:
                    f.write(','.join(processed_data[0].keys()) + '\n')
                    for row in processed_data:
                        f.write(','.join(str(v) for v in row.values()) + '\n')
            
            logging.info(f"Processed data saved to {csv_file_path}")
            return csv_file_path
        else:
            raise ValueError("Invalid data_type. Must be 'MITRE' or 'CVE'.")

        # Execute the command for MITRE processing
        logging.info(f"Executing: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error(f"Error processing {data_type}: {stderr.decode()}")
            if args.verbose:
                logging.debug(f"STDOUT: {stdout.decode()}")
                logging.debug(f"STDERR: {stderr.decode()}")
            return None

        # Log the standard output
        logging.info(stdout.decode())
        if args.verbose:
            logging.debug(f"STDOUT: {stdout.decode()}")
            logging.debug(f"STDERR: {stderr.decode()}")

        # For MITRE, process_mitre returns a list of file paths
        if data_type.upper() == "MITRE":
            raw_output = stdout.decode()
            logging.debug(f"Raw output from MITRE processor: {raw_output}")
            try:
                # Attempt to parse the stdout as a JSON list of file paths
                file_paths = json.loads(raw_output)
                if isinstance(file_paths, list):
                    return file_paths
                else:
                    logging.error(f"Unexpected output from MITRE processor: {file_paths}")
                    return None
            except json.JSONDecodeError:
                logging.error(f"Could not decode JSON from MITRE processor's output: {raw_output}")
                return None
        else:
            # For CVE, return the output file path
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

def generate_knowledge_graph(json_file_path: str, data_type: str, args: argparse.Namespace) -> str | None:
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
        if data_type.upper() == "CVE":
            # For CVE, we already generated the knowledge graph in process_data
            return json_file_path
        else:
            # For MITRE, use the new knowledge graph generator
            from ingestion.mitre_kg_generator import MITREKGGenerator
            
            generator = MITREKGGenerator()
            
            with open(json_file_path, 'r') as f:
                data = json.load(f)
            
            processed_data = generator.process(data)
            
            # Save to CSV
            file_name = os.path.splitext(os.path.basename(json_file_path))[0]
            csv_file_path = os.path.join("knowledge_graphs", f"{file_name}.csv")
            os.makedirs("knowledge_graphs", exist_ok=True)
            
            with open(csv_file_path, 'w') as f:
                if processed_data:
                    f.write(','.join(processed_data[0].keys()) + '\n')
                    for row in processed_data:
                        f.write(','.join(str(v) for v in row.values()) + '\n')
            
            logging.info(f"Knowledge graph saved to {csv_file_path}")
            return csv_file_path

    except FileNotFoundError:
        logging.error(f"File not found: {json_file_path}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        return None

def process_mitre_data(processed_files: list[str], data_type: str, args: argparse.Namespace) -> None:
    """
    Generates knowledge graphs for each processed MITRE file.

    Args:
        processed_files (list[str]): List of paths to the processed JSON files.
        data_type (str): Type of data (MITRE or CVE).
        args (argparse.Namespace): Command-line arguments.
    """
    for processed_file_path in processed_files:
        csv_file_path = generate_knowledge_graph(processed_file_path, data_type, args)
        if not csv_file_path:
            logging.error(f"Knowledge graph generation failed for {processed_file_path}.")
            sys.exit(1)  # Exit if KG generation fails

def main():
    """
    Main function to orchestrate the data processing pipeline.
    """
    parser = argparse.ArgumentParser(description="Process threat data (MITRE or CVE) based on the specified platform.")
    parser.add_argument("data_type", help="Type of data (MITRE or CVE)", nargs='?')
    parser.add_argument("platform", help="Target platform (e.g., containers, Windows, Linux)", nargs='?')
    parser.add_argument("json_file_path", help="Path to the input JSON file", nargs='?', default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)")
    parser.add_argument("--skip-kg", action="store_true", help="Skip knowledge graph generation")
    parser.add_argument("--embed", action="store_true", help="Embed the knowledge graph into the database")
    parser.add_argument("--data_type", help="Type of data (MITRE or CVE)", choices=['MITRE', 'CVE'])
    parser.add_argument("--platform", help="Target platform (e.g., containers, Windows, Linux)")
    parser.add_argument("--kg-directory", default="knowledge_graphs", help="Directory containing the knowledge graph CSV files")
    parser.add_argument("--processed-data", help="Path to the directory containing processed JSON files for KG generation", default=None)
    args = parser.parse_args()

    # Set logging level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.embed:
        if not (args.data_type and args.platform and args.kg_directory):
            parser.error("--embed requires data_type, platform, and kg_directory to be specified")
            sys.exit(1)

        csv_file_path = os.path.join(args.kg_directory, f"{args.data_type.lower()}.csv")

        # Call db_updater.py to embed the knowledge graph into the database
        command = [
            "python",
            "ingestion/db_updater.py",
            args.data_type.upper(),
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
        processed_files = process_data(args.json_file_path, args.data_type.upper(), args.platform, args)

        if processed_files:
            if args.data_type.upper() == "MITRE":
                process_mitre_data(processed_files, args.data_type, args)
            else:
                csv_file_path = generate_knowledge_graph(processed_files, args.data_type, args)
                if not csv_file_path:
                    logging.error("Knowledge graph generation failed.")
                    sys.exit(1)  # Exit if KG generation fails
        else:
            logging.error("Data processing failed.")
            sys.exit(1)  # Exit if data processing fails


if __name__ == "__main__":
    main()
