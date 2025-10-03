#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import subprocess
import shutil
import json
import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def filter_reports(input_dir, output_dir, ignored_cves=None, config_file=None, severity_filter=None):
    """
    Filter both JSON and HTML Aqua security reports to remove ignored vulnerabilities.
    
    Args:
        input_dir (str): Directory containing the original Aqua scan reports
        output_dir (str): Directory where filtered reports will be saved
        ignored_cves (list): List of CVE IDs to filter out
        config_file (str): Path to a configuration file containing ignored CVEs
        severity_filter (list): List of severity levels to include (e.g., ['high', 'critical'])
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Path to the input files
    json_input = os.path.join(input_dir, 'aqua-scan.json')
    html_input = os.path.join(input_dir, 'aqua-scan.html')
    
    # Path to the output files
    json_output = os.path.join(output_dir, 'aqua-scan-filtered.json')
    html_output = os.path.join(output_dir, 'aqua-scan-filtered.html')
    
    # Check if BeautifulSoup is installed for HTML filtering
    try:
        import importlib
        importlib.import_module('bs4')
        html_support = True
    except ImportError:
        logging.warning("BeautifulSoup not installed. HTML filtering will be skipped.")
        logging.warning("Install with: pip install beautifulsoup4")
        html_support = False
    
    # Add script directory to path for imports
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.append(script_dir)
    
    # Filter JSON report
    try:
        # Import the filter_ignored_vulnerabilities function
        from filter_ignored_vulnerabilities import filter_ignored_vulnerabilities, find_ignored_vulnerabilities_in_report
        
        if os.path.exists(json_input):
            logging.info(f"Filtering JSON report from {json_input}")
            
            # First, if no ignored CVEs are provided, detect them from the report
            if (ignored_cves is None or len(ignored_cves) == 0) and config_file is None:
                try:
                    with open(json_input, 'r') as f:
                        scan_data = json.load(f)
                    
                    detected_cves = find_ignored_vulnerabilities_in_report(scan_data)
                    if detected_cves:
                        logging.info(f"Automatically detected {len(detected_cves)} ignored CVEs in the report")
                        ignored_cves = detected_cves
                except Exception as e:
                    logging.error(f"Error detecting ignored CVEs: {str(e)}")
            
            result = filter_ignored_vulnerabilities(json_input, json_output, ignored_cves, severity_filter)
            if result:
                logging.info(f"Successfully filtered JSON report to {json_output}")
            else:
                logging.error("Failed to filter JSON report")
        else:
            logging.warning(f"JSON report not found at {json_input}")
    except ImportError:
        logging.error("Could not import filter_ignored_vulnerabilities module")
        return False
    
    # Filter HTML report
    if html_support:
        try:
            # Import the filter_html_report function
            from filter_html_report import filter_html_report
            
            if os.path.exists(html_input):
                logging.info(f"Filtering HTML report from {html_input}")
                result = filter_html_report(html_input, html_output, ignored_cves, severity_filter)
                if result:
                    logging.info(f"Successfully filtered HTML report to {html_output}")
                else:
                    logging.error("Failed to filter HTML report")
            else:
                logging.warning(f"HTML report not found at {html_input}")
        except ImportError:
            logging.error("Could not import filter_html_report module")
            return False
    
    # Copy any other files (e.g., styles.css)
    css_input = os.path.join(input_dir, 'styles.css')
    css_output = os.path.join(output_dir, 'styles.css')
    if os.path.exists(css_input) and not os.path.exists(css_output):
        shutil.copy2(css_input, css_output)
        logging.info(f"Copied styles.css to {css_output}")
    
    # Store the detected or provided CVEs in a file for reference
    if ignored_cves:
        cve_info_file = os.path.join(output_dir, 'ignored_cves.json')
        try:
            with open(cve_info_file, 'w') as f:
                json.dump({
                    'ignored_cves': ignored_cves,
                    'count': len(ignored_cves),
                    'source': 'auto-detected' if config_file is None and not sys.argv[0].endswith('ignored-cves') else 'user-provided'
                }, f, indent=2)
            logging.info(f"Stored ignored CVE information to {cve_info_file}")
        except Exception as e:
            logging.error(f"Error saving ignored CVE information: {str(e)}")
    
    # Create a detailed debug report
    debug_file = os.path.join(output_dir, 'debug_filtering.txt')
    try:
        with open(debug_file, 'w') as f:
            f.write("DEBUG REPORT FOR VULNERABILITY FILTERING\n")
            f.write("=======================================\n\n")
            
            f.write(f"Date and time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Script version: 2025-05-13-updated\n\n")
            
            f.write(f"Input JSON: {json_input}\n")
            f.write(f"Output JSON: {json_output}\n")
            f.write(f"Input HTML: {html_input}\n")
            f.write(f"Output HTML: {html_output}\n\n")
            
            f.write(f"Ignored CVEs ({len(ignored_cves) if ignored_cves else 0}):\n")
            if ignored_cves:
                for cve in ignored_cves:
                    f.write(f"  - {cve}\n")
            else:
                f.write("  None\n")
            
            if severity_filter:
                f.write(f"\nSeverity Filter Applied: {', '.join(severity_filter).upper()}\n")
                f.write("Only vulnerabilities with these severity levels are included in the report.\n")
            
            # Check if the filtered files exist and have expected content
            if os.path.exists(json_output):
                f.write(f"\nFiltered JSON file size: {os.path.getsize(json_output)} bytes\n")
                try:
                    with open(json_output, 'r') as jf:
                        filtered_data = json.load(jf)
                        
                    # Count vulnerabilities in the filtered report
                    resource_count = 0
                    direct_count = 0
                    
                    if 'resources' in filtered_data:
                        for resource in filtered_data['resources']:
                            if 'vulnerabilities' in resource:
                                resource_count += len(resource['vulnerabilities'])
                    
                    if 'vulnerabilities' in filtered_data:
                        direct_count = len(filtered_data['vulnerabilities'])
                    
                    f.write(f"\nVulnerability counts in filtered report:\n")
                    f.write(f"  - Resources vulnerabilities: {resource_count}\n")
                    f.write(f"  - Direct vulnerabilities: {direct_count}\n")
                    f.write(f"  - Total: {resource_count + direct_count}\n")
                    
                    # Check if any ignored CVEs remain in the filtered data
                    remaining_ignored = []
                    
                    if ignored_cves:
                        if 'resources' in filtered_data:
                            for resource in filtered_data['resources']:
                                if 'vulnerabilities' in resource:
                                    for vuln in resource['vulnerabilities']:
                                        if 'name' in vuln and any(cve.lower() == vuln['name'].lower() for cve in ignored_cves):
                                            remaining_ignored.append(f"{vuln['name']} (in resources)")
                        
                        if 'vulnerabilities' in filtered_data:
                            for vuln in filtered_data['vulnerabilities']:
                                if 'name' in vuln and any(cve.lower() == vuln['name'].lower() for cve in ignored_cves):
                                    remaining_ignored.append(f"{vuln['name']} (in direct)")
                    
                    if remaining_ignored:
                        f.write("\nWARNING: Found ignored CVEs still present in filtered report:\n")
                        for cve in remaining_ignored:
                            f.write(f"  - {cve}\n")
                    else:
                        f.write("\nNo ignored CVEs found in filtered report. Filtering appears successful.\n")
                        
                except Exception as e:
                    f.write(f"\nError analyzing filtered JSON: {str(e)}\n")
            else:
                f.write("\nWARNING: Filtered JSON file not found!\n")
                
            if os.path.exists(html_output):
                f.write(f"\nFiltered HTML file size: {os.path.getsize(html_output)} bytes\n")
            else:
                f.write("\nWARNING: Filtered HTML file not found!\n")
                
            f.write("\n\nEnd of debug report\n")
        
        logging.info(f"Created detailed debug report at {debug_file}")
    except Exception as e:
        logging.error(f"Error creating debug report: {str(e)}")
    
    return True

def main():
    parser = argparse.ArgumentParser(description='Filter Aqua security reports to remove ignored vulnerabilities')
    parser.add_argument('--input-dir', default='artifacts', help='Directory containing the original Aqua scan reports')
    parser.add_argument('--output-dir', default='filtered-artifacts', help='Directory where filtered reports will be saved')
    parser.add_argument('--ignored-cves', nargs='+', help='List of CVE IDs to filter out')
    parser.add_argument('--config-file', help='Path to a configuration file containing ignored CVEs')
    parser.add_argument('--severity-filter', nargs='+', help='List of severity levels to include (e.g., high critical)')
    
    args = parser.parse_args()
    
    success = filter_reports(args.input_dir, args.output_dir, args.ignored_cves, args.config_file, args.severity_filter)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 