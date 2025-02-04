import argparse
import json
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PLATFORM_MAPPING = {
    "containers": ["container", "containers", "docker", "podman", "kubernetes"]
}

def process_mitre(json_file_path, platform):
    """
    Processes a MITRE ATT&CK JSON file, filtering techniques based on the specified platform.

    Args:
        json_file_path (str): The path to the MITRE ATT&CK JSON file.
        platform (str): A string specifying the target platform (e.g., "containers", "Windows", "Linux").

    Returns:
        dict: The processed JSON data, or None if no relevant techniques are found.
    """

    try:
        with open(json_file_path, 'r') as f:
            mitre_data = json.load(f)
    except FileNotFoundError:
        logging.error(f"File not found: {json_file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in: {json_file_path}")
        return None

    def get_expanded_platforms(target_platform):
        """
        Returns a list of expanded platform terms based on the PLATFORM_MAPPING.
        If the target_platform is not in the mapping, it returns a list containing only the target_platform.
        """
        return PLATFORM_MAPPING.get(target_platform, [target_platform])

    def platform_check(mitre_object, target_platform):
        """
        Checks if a MITRE ATT&CK object is relevant to the specified platform.

        Args:
            mitre_object (dict): A MITRE ATT&CK object.
            target_platform (str): A string specifying the target platform.

        Returns:
            bool: True if the object is relevant, False otherwise.
        """
        expanded_platforms = get_expanded_platforms(target_platform)
        object_platforms = mitre_object.get("x_mitre_platforms", [])

        if not object_platforms:
            if "all" in object_platforms:
                logging.debug(f"Technique {mitre_object.get('name')} retained due to platform match: all")
                return True
            return False

        for expanded_platform in expanded_platforms:
            if expanded_platform in object_platforms:
                logging.debug(f"Technique {mitre_object.get('name')} retained due to platform match: {expanded_platform}")
                return True

        return False

    # Filter the MITRE ATT&CK objects based on the platform
    filtered_objects = []
    for mitre_object in mitre_data.get("objects", []):
        if mitre_object.get("type") == "attack-pattern":
            if platform_check(mitre_object, platform):
                filtered_objects.append(mitre_object)
            else:
                logging.debug(f"Technique {mitre_object.get('name')} excluded due to platform mismatch")

    # Create a new MITRE ATT&CK JSON structure with the filtered objects
    filtered_data = {
        "objects": filtered_objects,
        "type": mitre_data.get("type"),
        "id": mitre_data.get("id"),
        "spec_version": mitre_data.get("spec_version")
    }

    if not filtered_objects:
        logging.warning(f"No relevant techniques found for platform {platform}")
        return None

    return filtered_data


def main():
    """
    Main function to execute MITRE ATT&CK data processing.
    """
    parser = argparse.ArgumentParser(description="Process MITRE ATT&CK JSON files for a specific platform.")
    parser.add_argument("json_file_path", help="Path to the MITRE ATT&CK JSON file")
    parser.add_argument("platform", help="Target platform (e.g., containers, Windows, Linux)")
    parser.add_argument("--output_dir", default="output", help="Directory to save processed MITRE ATT&CK data (default: output)")
    args = parser.parse_args()

    output_dir = args.output_dir

    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Extract filename from path
    file_name = os.path.basename(args.json_file_path)
    output_file_path = os.path.join(output_dir, file_name)

    try:
        logging.info(f"Starting MITRE ATT&CK processing for {args.json_file_path}")
        processed_data = process_mitre(args.json_file_path, args.platform)

        if processed_data is not None:
            logging.info(f"Found relevant techniques for platform {args.platform}")
            with open(output_file_path, "w") as outfile:
                json.dump(processed_data, outfile, indent=4)
            print(f"Processed data saved to: {output_file_path}")
        else:
            logging.warning(f"No relevant techniques found in {args.json_file_path} for platform {args.platform}")
            print("No relevant techniques found.")

    except Exception as e:
        logging.error(f"Failed to process MITRE ATT&CK file: {str(e)}", exc_info=True)
        print(f"Error processing MITRE ATT&CK file: {str(e)}")


if __name__ == "__main__":
    main()
