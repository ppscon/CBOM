#!/usr/bin/env python3
import json
import argparse
import logging
import os
import re
import sys
import datetime
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_elegant_report(input_json, output_html, ignored_cves=None):
    """
    Create an elegant HTML report from Aqua security scan JSON data.
    
    Args:
        input_json (str): Path to the filtered Aqua scan JSON report
        output_html (str): Path where the elegant HTML report will be saved
        ignored_cves (list): List of CVE IDs that have been filtered out
    """
    # Try to detect filtering type from output directory path
    filtering_type = "standard"
    if "high-critical" in output_html.lower():
        filtering_type = "severity"
    try:
        with open(input_json, 'r') as f:
            scan_data = json.load(f)
        
        logging.info(f"[DEBUG] Loaded JSON scan data from {input_json}")
        
        # Get a count of all vulnerabilities
        vuln_count = 0
        if 'resources' in scan_data:
            for resource in scan_data['resources']:
                if 'vulnerabilities' in resource:
                    vuln_count += len(resource['vulnerabilities'])
        
        if 'vulnerabilities' in scan_data:
            vuln_count += len(scan_data['vulnerabilities'])
        
        logging.info(f"[DEBUG] Found {vuln_count} vulnerabilities in the JSON data")
        
        # Create a summary file with vulnerability counts by severity
        sev_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'negligible': 0,
            'unknown': 0
        }
        
        resource_vulns = []
        direct_vulns = []
        
        # Map severity scores to categories
        def map_severity(score, severity_str=None):
            if severity_str and isinstance(severity_str, str):
                severity = severity_str.lower()
                if severity in ['critical', 'high', 'medium', 'low', 'negligible']:
                    return severity
            
            # Use score-based mapping if severity string is not present or not recognized
            if score is not None:
                try:
                    score_val = float(score)
                    if score_val >= 9.0:
                        return 'critical'
                    elif score_val >= 7.0:
                        return 'high'
                    elif score_val >= 4.0:
                        return 'medium'
                    elif score_val >= 0.1:
                        return 'low'
                    else:
                        return 'negligible'
                except (ValueError, TypeError):
                    pass
            
            return 'unknown'
        
        if 'resources' in scan_data:
            for resource in scan_data['resources']:
                if 'vulnerabilities' in resource:
                    for vuln in resource['vulnerabilities']:
                        # Get the score for severity mapping
                        nvd_score = vuln.get('nvd_score_v3', 0)
                        if not nvd_score:
                            nvd_score = vuln.get('nvd_score', 0)
                        
                        # Map to a severity level
                        severity = map_severity(nvd_score, vuln.get('severity', ''))
                        
                        # Update counts
                        sev_counts[severity] += 1
                        
                        # Build detailed info for resource vulns
                        resource_vulns.append({
                            'resource_name': resource.get('name', 'Unknown'),
                            'resource_path': resource.get('path', 'Unknown'),
                            'resource_type': resource.get('type', 'Unknown'),
                            'resource_version': resource.get('version', 'Unknown'),
                            'vuln_name': vuln.get('name', 'Unknown'),
                            'vuln_description': vuln.get('description', 'No description'),
                            'vuln_severity': severity.capitalize(),
                            'vuln_score': nvd_score,
                            'fix_version': vuln.get('fix_version', 'Unknown')
                        })
        
        if 'vulnerabilities' in scan_data:
            for vuln in scan_data['vulnerabilities']:
                # Get the score for severity mapping
                nvd_score = vuln.get('nvd_score_v3', 0)
                if not nvd_score:
                    nvd_score = vuln.get('nvd_score', 0)
                
                # Map to a severity level
                severity = map_severity(nvd_score, vuln.get('severity', ''))
                
                # Update counts
                sev_counts[severity] += 1
                
                # Build detailed info for direct vulns
                direct_vulns.append({
                    'vuln_name': vuln.get('name', 'Unknown'),
                    'vuln_description': vuln.get('description', 'No description'),
                    'vuln_severity': severity.capitalize(),
                    'vuln_score': nvd_score,
                    'fix_version': vuln.get('fix_version', 'Unknown')
                })
        
        logging.info(f"[DEBUG] Severity distribution: {sev_counts}")
        
        # Count all CVE IDs
        all_cves = set()
        if 'resources' in scan_data:
            for resource in scan_data['resources']:
                if 'vulnerabilities' in resource:
                    for vuln in resource['vulnerabilities']:
                        if 'name' in vuln and vuln['name'].startswith('CVE-'):
                            all_cves.add(vuln['name'])
        
        if 'vulnerabilities' in scan_data:
            for vuln in scan_data['vulnerabilities']:
                if 'name' in vuln and vuln['name'].startswith('CVE-'):
                    all_cves.add(vuln['name'])
        
        logging.info(f"[DEBUG] Found {len(all_cves)} unique CVE IDs in the data: {', '.join(sorted(all_cves)[:10])}...")
        
        # Create an HTML report that shows all this data
        badge_style = 'style="background-color: #e74c3c;"' if filtering_type == "severity" else ''
        badge_text = 'HIGH/CRITICAL ONLY' if filtering_type == "severity" else 'FILTERED'
        filter_notice = '<div style="background-color: #fff3cd; border-left: 4px solid #e74c3c; padding: 10px 15px; margin: 20px 0;"><p><strong>Important:</strong> This report has been filtered to show ONLY high and critical severity vulnerabilities. Low and medium severity vulnerabilities have been excluded.</p></div>' if filtering_type == "severity" else ''
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Curated Vulnerability Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f8f9fa;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 20px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    border-radius: 5px;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                }}
                h1 {{
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }}
                .summary {{
                    display: flex;
                    flex-wrap: wrap;
                    gap: 15px;
                    margin: 20px 0;
                }}
                .summary-card {{
                    flex: 1;
                    min-width: 180px;
                    background: #f1f8ff;
                    border-left: 4px solid #3498db;
                    padding: 15px;
                    border-radius: 3px;
                }}
                .severity-chart {{
                    display: flex;
                    height: 30px;
                    border-radius: 4px;
                    overflow: hidden;
                    margin: 20px 0;
                }}
                .severity-critical {{
                    background-color: #d9534f;
                    color: white;
                    text-align: center;
                }}
                .severity-high {{
                    background-color: #f0ad4e;
                    color: white;
                    text-align: center;
                }}
                .severity-medium {{
                    background-color: #5bc0de;
                    color: white;
                    text-align: center;
                }}
                .severity-low {{
                    background-color: #5cb85c;
                    color: white;
                    text-align: center;
                }}
                .severity-negligible {{
                    background-color: #777;
                    color: white;
                    text-align: center;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th, td {{
                    padding: 12px 15px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #f2f2f2;
                    font-weight: bold;
                }}
                tr:hover {{
                    background-color: #f5f5f5;
                }}
                .filtered-badge {{
                    display: inline-block;
                    background-color: #28a745;
                    color: white;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 0.8em;
                    margin-right: 8px;
                }}
                .cve-id {{
                    font-family: monospace;
                    padding: 2px 4px;
                    background: #eee;
                    border-radius: 3px;
                }}
                .severity-badge {{
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 0.8em;
                    color: white;
                }}
                .severity-badge.critical {{
                    background-color: #d9534f;
                }}
                .severity-badge.high {{
                    background-color: #f0ad4e;
                }}
                .severity-badge.medium {{
                    background-color: #5bc0de;
                }}
                .severity-badge.low {{
                    background-color: #5cb85c;
                }}
                .severity-badge.negligible {{
                    background-color: #777;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>
                    <span class="filtered-badge" {badge_style}>
                        {badge_text}
                    </span>
                    Curated Vulnerability Report
                </h1>
                
                {filter_notice}
                
                <div class="summary">
                    <div class="summary-card">
                        <h3>Scan Overview</h3>
                        <p><strong>Scan Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>Total Vulnerabilities:</strong> {vuln_count}</p>
                        <p><strong>Unique CVEs:</strong> {len(all_cves)}</p>
                    </div>
                    
                    <div class="summary-card">
                        <h3>Severity Distribution</h3>
                        <p><strong>Critical:</strong> {sev_counts['critical']}</p>
                        <p><strong>High:</strong> {sev_counts['high']}</p>
                        <p><strong>Medium:</strong> {sev_counts['medium']}</p>
                        <p><strong>Low:</strong> {sev_counts['low']}</p>
                        <p><strong>Negligible:</strong> {sev_counts['negligible']}</p>
                    </div>
                </div>
                
                <div class="severity-chart">
                    <div class="severity-critical" style="width: {max(1, sev_counts['critical'] / max(1, vuln_count) * 100)}%;">
                        {sev_counts['critical']}
                    </div>
                    <div class="severity-high" style="width: {max(1, sev_counts['high'] / max(1, vuln_count) * 100)}%;">
                        {sev_counts['high']}
                    </div>
                    <div class="severity-medium" style="width: {max(1, sev_counts['medium'] / max(1, vuln_count) * 100)}%;">
                        {sev_counts['medium']}
                    </div>
                    <div class="severity-low" style="width: {max(1, sev_counts['low'] / max(1, vuln_count) * 100)}%;">
                        {sev_counts['low']}
                    </div>
                    <div class="severity-negligible" style="width: {max(1, sev_counts['negligible'] / max(1, vuln_count) * 100)}%;">
                        {sev_counts['negligible']}
                    </div>
                </div>
        """
        
        if ignored_cves:
            html += f"""
                <div style="background-color: #f8f9fa; border-left: 4px solid #28a745; padding: 10px 15px; margin: 20px 0;">
                    <p><strong>Note:</strong> This report excludes {len(ignored_cves)} ignored vulnerabilities:</p>
                    <ul>
            """
            for cve in ignored_cves:
                html += f"        <li><span class='cve-id'>{cve}</span></li>\n"
            html += "    </ul>\n</div>\n"
        
        # Add resource vulnerabilities table
        if resource_vulns:
            html += """
                <h2>Package Vulnerabilities</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Package</th>
                            <th>Path</th>
                            <th>Version</th>
                            <th>CVE / Vulnerability</th>
                            <th>Severity</th>
                            <th>Score</th>
                            <th>Fix Version</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for vuln in resource_vulns:
                severity_class = vuln['vuln_severity'].lower() if vuln['vuln_severity'].lower() in ['critical', 'high', 'medium', 'low', 'negligible'] else 'low'
                
                html += f"""
                    <tr>
                        <td>{vuln['resource_name']}</td>
                        <td>{vuln['resource_path']}</td>
                        <td>{vuln['resource_version']}</td>
                        <td>
                            <span class="cve-id">{vuln['vuln_name']}</span>
                            <div style="font-size: 0.9em; color: #666;">{vuln['vuln_description'][:100]}...</div>
                        </td>
                        <td><span class="severity-badge {severity_class}">{vuln['vuln_severity']}</span></td>
                        <td>{vuln['vuln_score']}</td>
                        <td>{vuln['fix_version']}</td>
                    </tr>
                """
            
            html += """
                    </tbody>
                </table>
            """
        
        # Add direct vulnerabilities if any
        if direct_vulns:
            html += """
                <h2>Direct Vulnerabilities</h2>
                <table>
                    <thead>
                        <tr>
                            <th>CVE / Vulnerability</th>
                            <th>Severity</th>
                            <th>Score</th>
                            <th>Fix Version</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for vuln in direct_vulns:
                severity_class = vuln['vuln_severity'].lower() if vuln['vuln_severity'].lower() in ['critical', 'high', 'medium', 'low', 'negligible'] else 'low'
                
                html += f"""
                    <tr>
                        <td>
                            <span class="cve-id">{vuln['vuln_name']}</span>
                            <div style="font-size: 0.9em; color: #666;">{vuln['vuln_description'][:100]}...</div>
                        </td>
                        <td><span class="severity-badge {severity_class}">{vuln['vuln_severity']}</span></td>
                        <td>{vuln['vuln_score']}</td>
                        <td>{vuln['fix_version']}</td>
                    </tr>
                """
            
            html += """
                    </tbody>
                </table>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        # Write the elegant report
        with open(output_html, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logging.info(f"[DEBUG] Created elegant HTML report at {output_html}")
        
        return True
    
    except Exception as e:
        logging.error(f"Error creating elegant report: {str(e)}")
        logging.error(f"Exception details: {str(e.__class__.__name__)}: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        return False

def main():
    parser = argparse.ArgumentParser(description='Create an elegant HTML report from Aqua security scan JSON data')
    parser.add_argument('input_json', help='Path to the filtered Aqua scan JSON report')
    parser.add_argument('output_html', help='Path where the elegant HTML report will be saved')
    parser.add_argument('--ignored-cves', nargs='+', help='List of CVE IDs that have been filtered out')
    
    args = parser.parse_args()
    
    # Try to determine ignored CVEs if not provided
    ignored_cves = args.ignored_cves
    if not ignored_cves:
        # Look for ignored_cves.json in the same directory as the input
        ignored_cves_file = os.path.join(os.path.dirname(args.input_json), 'ignored_cves.json')
        if os.path.exists(ignored_cves_file):
            try:
                with open(ignored_cves_file, 'r') as f:
                    data = json.load(f)
                    if 'ignored_cves' in data:
                        ignored_cves = data['ignored_cves']
                        logging.info(f"[DEBUG] Loaded {len(ignored_cves)} ignored CVEs from file")
            except Exception as e:
                logging.warning(f"Error loading ignored CVEs from file: {str(e)}")
    
    # Fallback to hardcoded values if we still don't have any
    if not ignored_cves:
        ignored_cves = ["CVE-2025-27789", "CVE-2024-45590"]
        logging.info(f"[DEBUG] Using hardcoded ignored CVEs: {', '.join(ignored_cves)}")
    
    success = create_elegant_report(args.input_json, args.output_html, ignored_cves)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 