#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
import json
import datetime
import subprocess
from bs4 import BeautifulSoup

# Updated 2025-05-13: Added variable substitution for shell-style variables in HTML
# Updated 2025-05-13: Added more detailed debugging information
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Example CVEs for testing - this should not be used in production
# Instead, we'll use the same dynamic approach as in filter_ignored_vulnerabilities.py
EXAMPLE_IGNORED_CVES = [
    "CVE-2025-27789"
]

def replace_variables(text):
    """
    Replace shell-style variables in text with their actual values.
    
    Args:
        text (str): Text containing variables to replace
        
    Returns:
        str: Text with variables replaced
    """
    if not text:
        return text
    
    # Replace ${GITHUB_SHA} with the actual commit SHA
    github_sha = os.environ.get('GITHUB_SHA', 'Unknown commit')
    text = re.sub(r'\${GITHUB_SHA}', github_sha, text)
    logging.info(f"[DEBUG] Replaced GITHUB_SHA with: {github_sha}")
    
    # Replace $(date) with the actual date
    current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    text = re.sub(r'\$\(date\)', current_date, text)
    logging.info(f"[DEBUG] Replaced date with: {current_date}")
    
    return text

def filter_html_report(input_file, output_file, ignored_cves=None, severity_filter=None):
    """
    Filter out ignored vulnerabilities from Aqua security HTML report.
    
    Args:
        input_file (str): Path to the original Aqua scan HTML report
        output_file (str): Path where the filtered report will be saved
        ignored_cves (list): List of CVE IDs that should be filtered out
        severity_filter (list): List of severity levels to include (e.g., ['high', 'critical'])
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        logging.info(f"[DEBUG] Loaded HTML report from {input_file}")
        
        # First, replace all variables in the raw HTML content
        html_content = replace_variables(html_content)
        logging.info("[DEBUG] Replaced all shell-style variables in HTML content")
        
        # If ignored_cves not provided, try to get them from environment or JSON report
        if ignored_cves is None or len(ignored_cves) == 0:
            # First try environment variables
            env_ignored = os.environ.get('AQUA_IGNORED_CVES', '')
            if env_ignored:
                ignored_cves = [cve.strip() for cve in env_ignored.split(',')]
                logging.info(f"[DEBUG] Using {len(ignored_cves)} ignored CVEs from environment variable")
            else:
                # Try to find corresponding JSON report to extract ignored CVEs
                json_report_path = os.path.join(os.path.dirname(input_file), 
                                               os.path.basename(input_file).replace('.html', '.json'))
                
                if os.path.exists(json_report_path):
                    try:
                        # Import the function to avoid code duplication
                        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
                        from filter_ignored_vulnerabilities import find_ignored_vulnerabilities_in_report
                        
                        with open(json_report_path, 'r') as f:
                            scan_data = json.load(f)
                        
                        ignored_cves = find_ignored_vulnerabilities_in_report(scan_data)
                        logging.info(f"[DEBUG] Extracted {len(ignored_cves)} ignored CVEs from JSON report")
                    except Exception as e:
                        logging.warning(f"[DEBUG] Could not extract ignored CVEs from JSON report: {str(e)}")
        
        # Fallback to config file if we still have none
        if ignored_cves is None or len(ignored_cves) == 0:
            config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ignored_cves_config.json")
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                        if 'ignored_cves' in config:
                            ignored_cves = config['ignored_cves']
                            logging.info(f"[DEBUG] Loaded {len(ignored_cves)} ignored CVEs from config file: {', '.join(ignored_cves)}")
                except Exception as e:
                    logging.warning(f"[DEBUG] Error reading config file: {str(e)}")
        
        # Make sure ignored_cves list is properly formatted and all are lowercase for case-insensitive matching
        if ignored_cves:
            ignored_cves = [cve.strip() for cve in ignored_cves]
            logging.info(f"[DEBUG] Will filter out these CVEs: {', '.join(ignored_cves)}")
        else:
            ignored_cves = []
            logging.warning("[DEBUG] No ignored CVEs found from any source. Report will remain unchanged.")
         
        # Create a debug file to confirm which CVEs we're filtering   
        debug_file = os.path.join(os.path.dirname(output_file), "debug_html_filter_list.txt")
        with open(debug_file, 'w') as f:
            f.write(f"HTML Filter - CVEs to filter out:\n")
            for cve in ignored_cves:
                f.write(f"{cve}\n")
            f.write("\n\nThis file was created by filter_html_report.py for debugging purposes.\n")
            f.write(f"Version: 2025-05-13 - Fixed filtering to REMOVE ignored CVEs\n")
            
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find vulnerability sections - more targeted approach
        removed_count = 0
        removed_cves = []
        
        # Debug: Save original HTML structure before filtering
        debug_original_html = os.path.join(os.path.dirname(output_file), "debug_original_html_structure.txt")
        try:
            with open(debug_original_html, 'w', encoding='utf-8') as f:
                tables = soup.find_all('table')
                f.write(f"Number of tables in original HTML: {len(tables)}\n")
                
                vuln_tables = [t for t in tables if 'vulnerability' in str(t).lower() or 'cve' in str(t).lower()]
                f.write(f"Number of vulnerability tables: {len(vuln_tables)}\n")
                
                rows = soup.find_all('tr')
                f.write(f"Number of rows in original HTML: {len(rows)}\n")
                
                # Look for all CVE references
                all_cves = set()
                cve_pattern = re.compile(r'\bCVE-\d{4}-\d+\b', re.IGNORECASE)
                for text in soup.find_all(string=cve_pattern):
                    match = cve_pattern.search(text)
                    if match:
                        all_cves.add(match.group())
                
                f.write(f"\nAll CVEs found in original HTML ({len(all_cves)}):\n")
                for cve in sorted(all_cves):
                    f.write(f"  - {cve}\n")
        except Exception as e:
            logging.error(f"Error creating original HTML structure debug file: {str(e)}")
            
        # NEW APPROACH: More careful filtering that won't break the table structure
        
        # Normalize severity filter
        if severity_filter:
            severity_filter = [s.lower().strip() for s in severity_filter]
            logging.info(f"[DEBUG] Will filter for these severity levels: {', '.join(severity_filter)}")
        
        # 1. First identify the vulnerability table sections
        vuln_tables = [t for t in soup.find_all('table') if 'vulnerability' in str(t).lower() or 'cve' in str(t).lower()]
        
        # 2. Filter by CVE IDs if provided
        if ignored_cves:
            for cve_id in ignored_cves:
                # We'll use exact pattern matching with word boundaries
                cve_pattern = re.compile(r'\b' + re.escape(cve_id) + r'\b', re.IGNORECASE)
                found_for_this_cve = False
                
                # Find all rows in all tables
                for table in vuln_tables:
                    rows_with_cve = []
                    for row in table.find_all('tr'):
                        if cve_pattern.search(str(row)):
                            rows_with_cve.append(row)
                    
                    # Remove only those specific rows
                    for row in rows_with_cve:
                        logging.info(f"[DEBUG] Found and removing row with {cve_id}")
                        row.decompose()
                        removed_count += 1
                        found_for_this_cve = True
                
                # Also look for any standalone CVE items (often in list items)
                cve_items = soup.find_all(['li', 'div', 'span'], string=cve_pattern)
                for item in cve_items:
                    logging.info(f"[DEBUG] Found and removing standalone item with {cve_id}")
                    item.decompose()
                    removed_count += 1
                    found_for_this_cve = True
                
                if found_for_this_cve:
                    removed_cves.append(cve_id)
                    logging.info(f"[DEBUG] Successfully removed entries for {cve_id}")
        
        # 3. Filter by severity if provided
        if severity_filter:
            removed_severities = []
            # Common severity patterns in HTML
            severity_patterns = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown']
            
            for table in vuln_tables:
                for row in table.find_all('tr'):
                    row_text = str(row).lower()
                    # Check if row contains severity information
                    found_severity = None
                    for sev in severity_patterns:
                        if sev in row_text:
                            found_severity = sev
                            break
                    
                    # If we found a severity and it's NOT in our filter list, remove the row
                    if found_severity and found_severity not in severity_filter:
                        logging.info(f"[DEBUG] Removing row with severity: {found_severity}")
                        row.decompose()
                        removed_count += 1
                        removed_severities.append(found_severity)
        
        # Create a summary file for debugging
        debug_summary_file = os.path.join(os.path.dirname(output_file), "debug_html_filter_summary.txt")
        with open(debug_summary_file, 'w') as f:
            f.write(f"HTML FILTERING SUMMARY:\n")
            f.write(f"---------------------\n")
            f.write(f"Removed entries: {removed_count}\n\n")
            
            if removed_cves:
                f.write(f"CVEs successfully filtered ({len(removed_cves)}):\n")
                for cve in sorted(set(removed_cves)):
                    f.write(f"  - {cve}\n")
            
            if severity_filter:
                f.write(f"\nSeverity filter applied - only including: {', '.join(severity_filter)}\n")
                if 'removed_severities' in locals():
                    f.write(f"Removed entries by severity: {len(removed_severities)}\n")
                
            f.write("\n\nThis file was created by filter_html_report.py for debugging purposes.\n")
            f.write(f"Version: 2025-05-13 - Fixed filtering to REMOVE ignored CVEs\n")
        
        # Add custom styling
        if soup.head:
            style_tag = soup.new_tag('style')
            style_tag.string = """
            .filtered-notice {
                background-color: #f8f9fa;
                border-left: 4px solid #28a745;
                padding: 10px 15px;
                margin: 20px 0;
                border-radius: 3px;
                font-family: Arial, sans-serif;
            }
            .filtered-badge {
                display: inline-block;
                background-color: #28a745;
                color: white;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.8em;
                margin-right: 8px;
            }
            """
            soup.head.append(style_tag)
        
        # Add a notice at the top of the body that this is a filtered report
        if soup.body:
            notice_div = soup.new_tag('div')
            notice_div['class'] = 'filtered-notice'
            
            badge_span = soup.new_tag('span')
            badge_span['class'] = 'filtered-badge'
            
            # Customize badge and message based on filtering type
            if severity_filter:
                badge_span.string = 'FILTERED'
                badge_span['style'] = 'background-color: #e74c3c;'  # Red for severity filter
                notice_div.append(badge_span)
                notice_div.append(f' This report has been filtered to show only {", ".join(severity_filter).upper()} severity vulnerabilities')
            else:
                badge_span.string = 'FILTERED'
                notice_div.append(badge_span)
                notice_div.append(' This report has been filtered to exclude ignored vulnerabilities')
            
            # Add details of removed CVEs
            if removed_count > 0 and removed_cves:
                cve_list = soup.new_tag('p')
                cve_list.string = f"Removed {removed_count} entries related to ignored vulnerabilities: {', '.join(removed_cves)}"
                notice_div.append(cve_list)
            
            # Insert at the beginning of the body
            soup.body.insert(0, notice_div)
        
        # Write the filtered report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(str(soup))
        
        # Add another debugging step - dump table structure after filtering
        debug_tables_file = os.path.join(os.path.dirname(output_file), "debug_tables_after_filtering.txt")
        try:
            with open(debug_tables_file, 'w', encoding='utf-8') as f:
                tables = soup.find_all('table')
                f.write(f"Number of tables after filtering: {len(tables)}\n\n")
                
                for i, table in enumerate(tables):
                    f.write(f"TABLE {i+1}:\n")
                    f.write(f"Number of rows: {len(table.find_all('tr'))}\n")
                    
                    # Check if table has headers
                    headers = table.find_all('th')
                    if headers:
                        f.write("Headers: " + ", ".join([h.get_text().strip() for h in headers]) + "\n")
                    
                    # Sample some rows
                    rows = table.find_all('tr')
                    f.write(f"First 5 rows sample:\n")
                    for j, row in enumerate(rows[:5]):
                        f.write(f"  Row {j+1}: {row.get_text().strip()[:100]}...\n")
                    
                    f.write("\n")
        except Exception as e:
            logging.error(f"Error creating table structure debug file: {str(e)}")
            
        # Count vulnerabilities after filtering
        try:
            vuln_count = 0
            vuln_tables = [t for t in soup.find_all('table') if 'vulnerability' in str(t).lower() or 'cve' in str(t).lower()]
            for table in vuln_tables:
                vuln_count += len(table.find_all('tr')) - 1  # Subtract header row
            
            logging.info(f"[DEBUG] After filtering, found approximately {vuln_count} vulnerability entries")
            
            with open(os.path.join(os.path.dirname(output_file), "debug_vuln_count.txt"), 'w') as f:
                f.write(f"Vulnerability count after filtering: {vuln_count}\n")
        except Exception as e:
            logging.error(f"Error counting vulnerabilities: {str(e)}")
        
        # Add debugging output of filtered HTML for analysis
        debug_html_file = os.path.join(os.path.dirname(output_file), "debug_filtered_html_structure.txt")
        try:
            with open(debug_html_file, 'w', encoding='utf-8') as f:
                # Write a summary of the HTML structure for debugging
                f.write("HTML STRUCTURE AFTER FILTERING:\n")
                f.write("============================\n\n")
                
                # Count the main elements 
                tables = soup.find_all('table')
                f.write(f"Number of tables: {len(tables)}\n")
                
                # Count vulnerability-related elements
                vuln_elements = soup.find_all(['div', 'tr', 'section'], string=lambda s: s and ('vulnerability' in s.lower() or 'cve' in s.lower()))
                f.write(f"Number of vulnerability-related elements: {len(vuln_elements)}\n")
                
                # Check if any ignored CVEs still exist in the document
                remaining_ignored = []
                for cve_id in ignored_cves:
                    pattern = re.compile(r'\b' + re.escape(cve_id) + r'\b', re.IGNORECASE)
                    if soup.find_all(string=pattern):
                        remaining_ignored.append(cve_id)
                
                if remaining_ignored:
                    f.write(f"\nWARNING: Found {len(remaining_ignored)} ignored CVEs still present in filtered HTML:\n")
                    for cve in remaining_ignored:
                        f.write(f"  - {cve}\n")
                else:
                    f.write("\nNo ignored CVEs found in filtered HTML. Filtering appears successful.\n")
                
                # List the first 20 table rows to see what's in the report
                f.write("\nSample of table rows in the filtered report:\n")
                rows = soup.find_all('tr')
                for i, row in enumerate(rows[:20]):  # Just show the first 20 for brevity
                    f.write(f"\nRow {i+1}:\n{row.get_text()[:200]}...\n")
                
                f.write("\nThis file was created by filter_html_report.py for debugging purposes.\n")
        except Exception as e:
            logging.error(f"Error creating HTML structure debug file: {str(e)}")
        
        # Copy CSS file if it exists
        css_file = os.path.join(os.path.dirname(input_file), 'styles.css')
        if os.path.exists(css_file):
            output_css = os.path.join(os.path.dirname(output_file), 'styles.css')
            with open(css_file, 'r', encoding='utf-8') as src, open(output_css, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        
        if removed_count == 0:
            logging.warning("[DEBUG] No entries were removed from the HTML report. Filtering may not be working correctly.")
        else:
            logging.info(f"[DEBUG] Filtered out {removed_count} entries related to ignored vulnerabilities")
        
        logging.info(f"[DEBUG] Filtered HTML report saved to {output_file}")
        
        return True
    
    except Exception as e:
        logging.error(f"Error processing HTML report: {str(e)}")
        logging.error(f"Exception details: {str(e.__class__.__name__)}: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        return False

def main():
    parser = argparse.ArgumentParser(description='Filter ignored vulnerabilities from Aqua security HTML reports')
    parser.add_argument('input_file', help='Path to the original Aqua scan HTML report')
    parser.add_argument('output_file', help='Path where the filtered report will be saved')
    parser.add_argument('--ignored-cves', nargs='+', help='List of CVE IDs to filter out')
    parser.add_argument('--config-file', help='Path to a configuration file containing ignored CVEs')
    
    args = parser.parse_args()
    
    ignored_cves = []
    
    # If config file is provided, read ignored CVEs from it
    if args.config_file and os.path.exists(args.config_file):
        try:
            with open(args.config_file, 'r') as f:
                config = json.load(f)
                if 'ignored_cves' in config:
                    ignored_cves = config['ignored_cves']
                    logging.info(f"[DEBUG] Loaded {len(ignored_cves)} ignored CVEs from config file")
        except Exception as e:
            logging.error(f"Error loading config file: {str(e)}")
    
    # Command-line arguments take precedence
    if args.ignored_cves:
        ignored_cves = args.ignored_cves
        logging.info(f"[DEBUG] Using {len(ignored_cves)} ignored CVEs from command line arguments")
    
    success = filter_html_report(args.input_file, args.output_file, ignored_cves)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 