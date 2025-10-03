#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def map_severity_from_score(score_str):
    """Map a CVE score to a severity level."""
    try:
        score = float(score_str)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0.0:
            return "Low"
        else:
            return "Negligible"
    except (ValueError, TypeError):
        # If score can't be converted to float, return Medium as default
        return "Medium"

def process_html_report(input_file, output_file):
    """
    Process an HTML report to fix severity values and replace variables.
    
    Args:
        input_file (str): Path to the input HTML file
        output_file (str): Path where the processed file should be saved
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        logging.info(f"Processing HTML file: {input_file}")
        
        # 1. Replace shell-style variables
        github_sha = os.environ.get('GITHUB_SHA', 'latest')
        current_date = os.environ.get('BUILD_DATE', 
                                     os.popen('date "+%Y-%m-%d %H:%M:%S"').read().strip())
        
        vars_replaced = 0
        html_content_new = re.sub(r'\${GITHUB_SHA}', github_sha, html_content)
        if html_content_new != html_content:
            vars_replaced += 1
            html_content = html_content_new
            
        html_content_new = re.sub(r'\$\(date\)', current_date, html_content)
        if html_content_new != html_content:
            vars_replaced += 1
            html_content = html_content_new
            
        logging.info(f"Replaced {vars_replaced} variable occurrences: GITHUB_SHA={github_sha}, date={current_date}")
        
        # 2. Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 3. Fix severity values in the table
        rows_updated = 0
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Negligible': 0}
        
        # Find all table rows
        for row in soup.find_all('tr'):
            cells = row.find_all('td')
            
            # Skip header rows or rows with insufficient cells
            if not cells or len(cells) < 6:
                continue
                
            # Assuming structure: Package, Path, Version, CVE/Vulnerability, Severity, Score, Fix Version
            # Index mapping might differ based on your table structure
            try:
                score_cell = cells[5]  # Score is the 6th column (index 5)
                severity_cell = cells[4]  # Severity is the 5th column (index 4)
                
                score_text = score_cell.get_text(strip=True)
                severity_text = severity_cell.get_text(strip=True)
                
                # First check if there's already a severity badge with a valid value
                severity_span = severity_cell.find('span', class_='severity-badge')
                if severity_span:
                    current_severity = severity_span.get_text(strip=True)
                    if current_severity in severity_counts:
                        # Count existing severities if they're valid
                        severity_counts[current_severity] += 1
                        continue
                
                # Only update if severity is "Unknown"
                if severity_text == "Unknown":
                    # For score 0 or non-numeric scores, default to Medium
                    if not score_text or score_text == "0":
                        new_severity = "Medium"
                    else:
                        new_severity = map_severity_from_score(score_text)
                    
                    # Update the text and class in the severity cell
                    severity_span = severity_cell.find('span', class_='severity-badge')
                    if severity_span:
                        # Remove old class
                        for cls in list(severity_span.get('class', [])):
                            if cls != 'severity-badge':
                                severity_span['class'].remove(cls)
                        
                        # Add new class and text
                        severity_span['class'].append(new_severity.lower())
                        severity_span.string = new_severity
                        
                        rows_updated += 1
                        severity_counts[new_severity] += 1
                    else:
                        # If span doesn't exist, create a new one
                        new_span = soup.new_tag('span')
                        new_span['class'] = ['severity-badge', new_severity.lower()]
                        new_span.string = new_severity
                        severity_cell.clear()
                        severity_cell.append(new_span)
                        
                        rows_updated += 1
                        severity_counts[new_severity] += 1
            except Exception as e:
                logging.warning(f"Error processing row: {str(e)}")
                continue
        
        logging.info(f"Updated {rows_updated} severity values")
        logging.info(f"Severity distribution: Critical={severity_counts['Critical']}, High={severity_counts['High']}, Medium={severity_counts['Medium']}, Low={severity_counts['Low']}, Negligible={severity_counts['Negligible']}")
        
        # 4. Update the summary metrics in the page
        summary_cards = soup.find_all('div', class_='summary-card')
        metrics_updated = 0
        for card in summary_cards:
            if card.find('h3') and card.find('h3').get_text() == 'Severity Distribution':
                # Update the summary card with our counts
                paragraphs = card.find_all('p')
                for p in paragraphs:
                    text = p.get_text()
                    if 'Critical:' in text:
                        p.clear()
                        p.append(soup.new_tag('strong'))
                        p.strong.string = 'Critical:'
                        p.append(f" {severity_counts['Critical']}")
                        metrics_updated += 1
                    elif 'High:' in text:
                        p.clear()
                        p.append(soup.new_tag('strong'))
                        p.strong.string = 'High:'
                        p.append(f" {severity_counts['High']}")
                        metrics_updated += 1
                    elif 'Medium:' in text:
                        p.clear()
                        p.append(soup.new_tag('strong'))
                        p.strong.string = 'Medium:'
                        p.append(f" {severity_counts['Medium']}")
                        metrics_updated += 1
                    elif 'Low:' in text:
                        p.clear()
                        p.append(soup.new_tag('strong'))
                        p.strong.string = 'Low:'
                        p.append(f" {severity_counts['Low']}")
                        metrics_updated += 1
                    elif 'Negligible:' in text:
                        p.clear()
                        p.append(soup.new_tag('strong'))
                        p.strong.string = 'Negligible:'
                        p.append(f" {severity_counts['Negligible']}")
                        metrics_updated += 1
        
        logging.info(f"Updated {metrics_updated} severity metrics in summary cards")
        
        # 5. Update the severity chart
        chart_updated = False
        total = sum(severity_counts.values())
        chart = soup.find('div', class_='severity-chart')
        if chart:
            critical_bar = chart.find('div', class_='severity-critical')
            high_bar = chart.find('div', class_='severity-high')
            medium_bar = chart.find('div', class_='severity-medium')
            low_bar = chart.find('div', class_='severity-low')
            negligible_bar = chart.find('div', class_='severity-negligible')
            
            if critical_bar:
                critical_width = max(1, (severity_counts['Critical'] / max(1, total) * 100))
                critical_bar['style'] = f'width: {critical_width}%;'
                critical_bar.string = str(severity_counts['Critical'])
                
            if high_bar:
                high_width = max(1, (severity_counts['High'] / max(1, total) * 100))
                high_bar['style'] = f'width: {high_width}%;'
                high_bar.string = str(severity_counts['High'])
                
            if medium_bar:
                medium_width = max(1, (severity_counts['Medium'] / max(1, total) * 100))
                medium_bar['style'] = f'width: {medium_width}%;'
                medium_bar.string = str(severity_counts['Medium'])
                
            if low_bar:
                low_width = max(1, (severity_counts['Low'] / max(1, total) * 100))
                low_bar['style'] = f'width: {low_width}%;'
                low_bar.string = str(severity_counts['Low'])
                
            if negligible_bar:
                negligible_width = max(1, (severity_counts['Negligible'] / max(1, total) * 100))
                negligible_bar['style'] = f'width: {negligible_width}%;'
                negligible_bar.string = str(severity_counts['Negligible'])
            
            chart_updated = True
            logging.info(f"Updated severity chart with calculated widths based on {total} total vulnerabilities")
        
        # 6. Change the title to "Curated Vulnerability Report" if needed
        title_updated = False
        title_tag = soup.find('title')
        if title_tag and "Elegant" in title_tag.string:
            title_tag.string = "Curated Vulnerability Report"
            title_updated = True
            
        h1_tag = soup.find('h1')
        if h1_tag and "Elegant" in h1_tag.get_text():
            for child in list(h1_tag.children):
                if isinstance(child, str) and "Elegant" in child:
                    new_text = child.replace("Elegant Security Report", "Curated Vulnerability Report")
                    h1_tag.contents[h1_tag.contents.index(child)] = new_text
                    title_updated = True
        
        if title_updated:
            logging.info("Updated report title to 'Curated Vulnerability Report'")
        
        # 7. Write the processed file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(str(soup))
        
        logging.info(f"Successfully processed report and saved to {output_file}")
        
        # Create a backup of the original for debugging
        backup_file = f"{input_file}.bak"
        with open(backup_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logging.info(f"Created backup of original file at {backup_file}")
        
        # Print a summary of all modifications
        print("=" * 50)
        print("REPORT PROCESSING SUMMARY")
        print("=" * 50)
        print(f"Variables replaced: {vars_replaced}")
        print(f"Severity values updated: {rows_updated}")
        print(f"Summary metrics updated: {metrics_updated}")
        print(f"Chart updated: {'Yes' if chart_updated else 'No'}")
        print(f"Title updated: {'Yes' if title_updated else 'No'}")
        print(f"Total vulnerabilities: {total}")
        print(f"Severity distribution: Critical={severity_counts['Critical']}, High={severity_counts['High']}, " +
              f"Medium={severity_counts['Medium']}, Low={severity_counts['Low']}, Negligible={severity_counts['Negligible']}")
        print("=" * 50)
        
        return True
        
    except Exception as e:
        logging.error(f"Error processing HTML report: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        return False

def main():
    parser = argparse.ArgumentParser(description='Process HTML reports to fix severity values and replace variables')
    parser.add_argument('input_file', help='Path to the input HTML file')
    parser.add_argument('output_file', help='Path where the processed file should be saved')
    
    args = parser.parse_args()
    
    success = process_html_report(args.input_file, args.output_file)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 