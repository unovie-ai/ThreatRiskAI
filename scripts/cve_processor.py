import argparse
import json
import logging
import os
import re
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def process_cve(json_file_path, platform):
    """
    Processes a CVE JSON file, filtering records based on the specified platform.

    Args:
        json_file_path (str): The path to the CVE JSON file.
        platform (str): A string specifying the target platform (e.g., "containers", "Windows", "Linux").

    Returns:
        dict: The processed JSON data, or None if no relevant CVEs are found.
    """

    try:
        with open(json_file_path, 'r') as f:
            cve_data = json.load(f)
    except FileNotFoundError:
        logging.error(f"File not found: {json_file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in: {json_file_path}")
        return None

    # Validate CVE structure
    if not cve_data.get("containers", {}).get("cna", {}).get("affected"):
        logging.error(f"Invalid CVE format in {json_file_path}: Missing containers.cna.affected section")
        return None
        
    # Check if the CVE is rejected
    cve_id = cve_data.get("cveMetadata", {}).get("cveId", "Unknown CVE")
    if cve_data.get("cveMetadata", {}).get("state") == "REJECTED":
        logging.info(f"CVE {cve_id} is rejected, ignoring")
        return None

    # Extract CVE ID for logging
    cve_id = cve_data.get("cveMetadata", {}).get("cveId", "Unknown CVE")

    # Primary Check: platforms in affected products
    def primary_check(cve_record, target_platform):
        affected_products = cve_record.get("containers", {}).get("cna", {}).get("affected", [])
        if not affected_products:
            return False

        for product in affected_products:
            platforms = product.get("platforms", [])
            if platforms and target_platform in platforms:
                logging.debug(f"CVE {cve_id} retained due to platform match in affected products: {target_platform}")
                return True
        return False

    # Secondary Check: product and vendor names
    def secondary_check(cve_record, target_platform):
        affected_products = cve_record.get("containers", {}).get("cna", {}).get("affected", [])
        if not affected_products:
            return False

        for product in affected_products:
            product_name = product.get("product", "").lower()
            vendor_name = product.get("vendor", "").lower()

            if target_platform.lower() in product_name or target_platform.lower() in vendor_name:
                logging.debug(f"CVE {cve_id} retained due to product/vendor name match: {target_platform}")
                return True
        return False

    # Tertiary Check: descriptions
    def tertiary_check(cve_record, target_platform):
        descriptions = cve_record.get("containers", {}).get("cna", {}).get("descriptions", [])
        if not descriptions:
            return False

        for description in descriptions:
            description_text = description.get("value", "").lower()
            if target_platform.lower() in description_text:
                logging.debug(f"CVE {cve_id} retained due to description match: {target_platform}")
                return True
        return False

    # Perform the checks with detailed logging
    logging.info(f"Processing CVE {cve_id} for platform {platform}")
    
    if primary_check(cve_data, platform):
        logging.info(f"CVE {cve_id} passed primary platform check")
        return cve_data
        
    if secondary_check(cve_data, platform):
        logging.info(f"CVE {cve_id} passed secondary product/vendor name check")
        return cve_data
        
    if tertiary_check(cve_data, platform):
        logging.info(f"CVE {cve_id} passed tertiary description check")
        return cve_data

    logging.info(f"CVE {cve_id} does not match platform {platform} in any check")
    return None


def main():
    """
    Main function to demonstrate the CVE processing script.
    """
    # Example usage:
    json_file_path = "data/cve.json"  # Replace with your actual file path
    platform = "containers"
    output_dir = "temp"

    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Extract filename from path
    file_name = os.path.basename(json_file_path)
    output_file_path = os.path.join(output_dir, file_name)


    try:
        logging.info(f"Starting CVE processing for {json_file_path}")
        processed_data = process_cve(json_file_path, platform)

        if processed_data is not None:
            logging.info(f"Found relevant CVE {processed_data.get('cveMetadata', {}).get('cveId')} for platform {platform}")
            with open(output_file_path, "w") as outfile:
                json.dump(processed_data, outfile, indent=4)
            print(f"Processed data saved to: {output_file_path}")
        else:
            logging.warning(f"No relevant CVEs found in {json_file_path} for platform {platform}")
            print("No relevant CVEs found.")
            
    except Exception as e:
        logging.error(f"Failed to process CVE file: {str(e)}", exc_info=True)
        print(f"Error processing CVE file: {str(e)}")


if __name__ == "__main__":
    main()
