# Load environment variables (like API keys)
from dotenv import load_dotenv
load_dotenv()

# Import necessary libraries
import os
import groq
import requests
import urllib.parse

# Initialize Groq client with API key
groq_api_key = os.getenv("GROQ_API_KEY")
groq_client = groq.Groq(api_key=groq_api_key)

# Function to fetch MITRE ATT&CK data (not fully functional)
def get_mitre_attack_data(query):
    """
    (Optional) Fetch MITRE ATT&CK framework data related to a query.
    """
    url = f"https://api.mitre.org/attack/{query}"
    try:
        response = requests.get(url)
        data = response.json()
        return data
    except Exception as e:
        return f"Error fetching ATT&CK data: {str(e)}"

# Function to send alert to Slack
def send_slack_alert(message):
    """
    Send a notification message to a Slack channel using webhook.
    """
    slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if slack_webhook_url:
        payload = {"text": message}
        requests.post(slack_webhook_url, json=payload)
    else:
        print("Slack Webhook URL not set.")

# Function to analyze logs locally
def analyze_logs(log_text):
    """
    Check logs for suspicious keywords and send alerts if necessary.
    """
    if "unauthorized" in log_text.lower():
        cve_info = search_cve(log_text)
        mitre_info = get_mitre_attack_data(log_text)
        alert_message = f"Suspicious log detected:\n{log_text}\n\n{cve_info}"
        send_slack_alert(alert_message)
        return alert_message
    else:
        return "No threats detected."

# Function to search CVEs (vulnerabilities) from NVD API
def search_cve(query):
    """
    Search for known CVEs related to a keyword from the NVD database.
    """
    print(f"Searching CVEs for: {query}")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 3  # limit to 3 results
    }
    try:
        query_string = urllib.parse.urlencode(params)
        url = f"{base_url}?{query_string}"

        response = requests.get(url)

        if response.status_code != 200:
            return f"Error: Received status code {response.status_code}"

        results = response.json()
        vulnerabilities = results.get("vulnerabilities", [])

        if not vulnerabilities:
            return "No CVEs found for this query."

        formatted = ""
        for vuln in vulnerabilities:
            cve_id = vuln['cve']['id']
            description = vuln['cve']['descriptions'][0]['value']
            formatted += f"{cve_id}: {description}\n\n"

        return f"Top matching CVEs:\n{formatted.strip()}"

    except Exception as e:
        return f"Error searching CVEs: {str(e)}"

# Main Cybersecurity Agent
def cybersecurity_agent(log_query):
    """
    Main agent that analyzes logs using Groq LLM and searches for vulnerabilities.
    """
    system_prompt = (
        "You are a cybersecurity expert. "
        "First, analyze the user's input logs to detect any threats or suspicious activities. "
        "If a threat is found, suggest mitigation strategies."
    )
    user_prompt = f"Analyze this log: {log_query}"

    response = groq_client.chat.completions.create(
        model="llama3-70b-8192",  # You can switch model names here
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0
    )

    analysis = response.choices[0].message.content
    print(f"\n=== Threat Analysis ===\n{analysis}")

    cve_results = search_cve(log_query)
    print(f"\n=== CVE Search Results ===\n{cve_results}")

# Execute when run directly
if __name__ == "__main__":
    query = "unauthorized access attempt on port 8080"
    cybersecurity_agent(query)
