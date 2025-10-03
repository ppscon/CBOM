import json
import requests
import os

def read_aqua_scan_json(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print("Aqua scan JSON file not found.")
        return None
    except json.JSONDecodeError:
        print("Error decoding Aqua scan JSON file.")
        return None

def send_teams_notification(assignee, aqua_data):
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "default_value_if_not_found")

    # Extract relevant details from Aqua scan data
    resources = aqua_data.get("resources", [])
    all_vulnerabilities = []

    for resource in resources:
        vulnerabilities = resource.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_id = vuln.get("name")
            severity = vuln.get("aqua_severity")
            fix_version = vuln.get("fix_version")
            nvd_url = vuln.get("nvd_url")
            description = vuln.get("description")
            all_vulnerabilities.append({
                "CVE ID": cve_id,
                "Severity": severity,
                "Fix Version": fix_version,
                "NVD URL": nvd_url,
                "Description": description
            })

    adaptive_card_content = {
        "type": "AdaptiveCard",
        "version": "1.0",
        "body": [
            {
                "type": "TextBlock",
                "size": "Medium",
                "weight": "Bolder",
                "text": f"New vulnerability task assigned to {assignee}"
            },
            {
                "type": "TextBlock",
                "text": f"Found {len(all_vulnerabilities)} vulnerabilities."
            }
        ]
    }

    for vuln in all_vulnerabilities:
        adaptive_card_content["body"].append({
            "type": "TextBlock",
            "text": f"CVE ID: {vuln['CVE ID']}, Severity: {vuln['Severity']}, Fix: {vuln['Fix Version']}, [More info]({vuln['NVD URL']})"
        })

    headers = {"Content-Type": "application/json"}
    payload = json.dumps({
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": adaptive_card_content
            }
        ]
    })

    try:
        response = requests.post(webhook_url, headers=headers, data=payload)
        response.raise_for_status()
        return response.status_code
    except requests.RequestException as e:
        print(f"Failed to send Teams notification: {e}")
        return None

if __name__ == "__main__":
    assignee = 'Philip'
    aqua_scan_data = read_aqua_scan_json('artifacts/aqua-scan.json')

    if aqua_scan_data:
        send_teams_notification(assignee, aqua_scan_data)
