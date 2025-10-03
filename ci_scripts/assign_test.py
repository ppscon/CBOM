# import json
# import requests
# import os
#
# def send_teams_notification(assignee, task_details):
#     webhook_url = os.environ.get("TEAMS_WEBHOOK_URL")
#
#     if not webhook_url:
#         print("Webhook URL is not set.")
#         return None
#
#     headers = {"Content-Type": "application/json"}
#
#     # Adaptive Card content
#     card_content = {
#         "type": "AdaptiveCard",
#         "version": "1.0",
#         "body": [
#             {
#                 "type": "TextBlock",
#                 "size": "Medium",
#                 "weight": "Bolder",
#                 "text": f"New vulnerability task assigned to {assignee}"
#             },
#             {
#                 "type": "ColumnSet",
#                 "columns": [
#                     {
#                         "type": "Column",
#                         "items": [
#                             {"type": "TextBlock", "text": f"CVE: {task_details['CVE']}", "wrap": True},
#                             {"type": "TextBlock", "text": f"Severity: {task_details['Severity']}", "wrap": True},
#                             {"type": "TextBlock", "text": f"Fix Version: {task_details['Fix Version']}", "wrap": True}
#                         ]
#                     }
#                 ]
#             }
#         ]
#     }
#
#     payload = {
#         "type": "message",
#         "attachments": [
#             {
#                 "contentType": "application/vnd.microsoft.card.adaptive",
#                 "contentUrl": None,
#                 "content": card_content
#             }
#         ]
#     }
#
#     try:
#         response = requests.post(webhook_url, headers=headers, json=payload)
#         response.raise_for_status()  # Raise HTTPError for bad responses
#         return response.status_code
#     except requests.RequestException as e:
#         print(f"Failed to send Teams notification: {e}")
#         return None
#
# # Example use-case
# assignee = 'Philip'
# task_details = {'CVE': 'CVE-2021-4500', 'Severity': 'High', 'Fix Version': '1.2.3'}
# send_teams_notification(assignee, task_details)  # Send Teams notification
