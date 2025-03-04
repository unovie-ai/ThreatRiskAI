import argparse
import json
import logging
import os
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

PLATFORM_MAPPING = {
    "containers": ["container", "containers", "docker", "podman", "kubernetes"]
}


def normalize_platform(platform):
    """
    Converts the platform to lowercase for case-insensitive comparison.
    """
    return platform.lower() if platform else ""

def process_mitre(json_file_path, platform, args):
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

    def platform_check(mitre_object: Dict[str, Any], target_platform: str) -> bool:
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
            logging.debug(f"Technique {mitre_object.get('name')} excluded: Missing x_mitre_platforms")
            return False

        for expanded_platform in expanded_platforms:
            for object_platform in object_platforms:
                if normalize_platform(object_platform) == normalize_platform(expanded_platform):
                    logging.debug(f"Technique {mitre_object.get('name')} retained due to platform match: {expanded_platform}")
                    return True

        logging.debug(f"Technique {mitre_object.get('name')} excluded: No platform match")
        return False

    # Filter MITRE ATT&CK objects based on the platform
    filtered_techniques: List[Dict[str, Any]] = []
    all_objects: List[Dict[str, Any]] = mitre_data.get("objects", [])
    for mitre_object in all_objects:
        if mitre_object.get("type") == "attack-pattern":
            if platform_check(mitre_object, platform):
                filtered_techniques.append(mitre_object)
            else:
                logging.debug(
                    f"Technique {mitre_object.get('name')} excluded due to platform mismatch"
                )

    # Extract IDs of filtered techniques
    filtered_technique_ids = {
        technique.get("id") for technique in filtered_techniques
    }

    # Create individual JSON files for each filtered technique and its related objects
    for technique in filtered_techniques:
        technique_id = technique.get("id")
        if not technique_id:
            logging.warning(f"Technique has no ID: {technique.get('name')}")
            continue

        # Identify related objects for the current technique
        related_objects: List[Dict[str, Any]] = []
        for mitre_object in all_objects:
            if any(
                technique_id == ref
                for key, ref in mitre_object.items()
                if key.endswith("_ref") and isinstance(ref, str)
            ):
                related_objects.append(mitre_object)

        # Create a new JSON structure for the technique and its related objects
        combined_objects = [technique] + related_objects
        threat_data: Dict[str, Any] = {
            "objects": combined_objects,
            "type": mitre_data.get("type"),
            "id": mitre_data.get("id"),
            "spec_version": mitre_data.get("spec_version"),
        }

        # Save the data to a JSON file named after the technique's ID
        output_file_path = os.path.join(args.output_dir, f"{technique_id}.json")
        try:
            with open(output_file_path, "w") as outfile:
                json.dump(threat_data, outfile, indent=4)
            logging.info(f"Threat data saved to: {output_file_path}")
        except Exception as e:
            logging.error(f"Failed to save threat data to {output_file_path}: {str(e)}")

    if not filtered_techniques:
        logging.warning(f"No relevant techniques found for platform {platform}")
        return []

    return [os.path.join(args.output_dir, f"{technique.get('id')}.json") for technique in filtered_techniques]


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
        process_mitre(args.json_file_path, args.platform, args)

    except Exception as e:
        logging.error(f"Failed to process MITRE ATT&CK file: {str(e)}")
        print(f"Error processing MITRE ATT&CK file: {str(e)}")


if __name__ == "__main__":
    main()
