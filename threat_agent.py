from dotenv import load_dotenv
import os
import groq
import requests
import urllib.parse

load_dotenv()

groq_api_key = os.getenv("GROQ_API_KEY")
groq_client = groq.Groq(api_key=groq_api_key)


def get_mitre_attack_data(query):
    url = f"https://api.mitre.org/attack/{query}"
    try:
        response = requests.get(url)
        data = response.json()
        return data
    except Exception as e:
        return f"Error fetching ATT&CK data: {str(e)}"


def send_slack_alert(message):
    slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    payload = {"text": message}
    requests.post(slack_webhook_url, json=payload)


def analyze_logs(log_text):
    if "unauthorized" in log_text:
        cve_info = search_cve(log_text)
        mitre_info = get_mitre_attack_data(log_text)
        alert_message = f"Suspicious log found: {log_text}\n{cve_info}"
        send_slack_alert(alert_message)
        return alert_message
    else:
        return "No threats detected."

def search_cve(query):
    print(f"Searching CVEs for: {query}")
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 3  # limit results
    }
    
    try:
        # Build full URL
        query_string = urllib.parse.urlencode(params)
        url = f"{base_url}?{query_string}"
        
        response = requests.get(url)
        
        if response.status_code != 200:
            return f"Error: Received status code {response.status_code}"
        
        results = response.json()
        
        # Navigate the JSON structure
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
            

def cybersecurity_agent(log_query):
    system_prompt = (
        "You are a cybersecurity expert. "
        "First, carefully analyze the user's input logs to find any threats or suspicious activities. "
        "Then, if you find a threat, suggest a way to fix or mitigate it."
    )
    user_prompt = f"Analyze this log: {log_query}"

    response = groq_client.chat.completions.create(
        model="llama3-70b-8192",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0
    )

    analysis = response.choices[0].message.content
    print(f"\n=== Analysis ===\n{analysis}")

    cve_results = search_cve(log_query)
    print(f"\n=== CVE Search Results ===\n{cve_results}")

if __name__ == "__main__":
    query = "unauthorized access attempt on port 8080"
    cybersecurity_agent(query)