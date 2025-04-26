from dotenv import load_dotenv
import os
import groq
import requests

load_dotenv()

groq_api_key = os.getenv("GROQ_API_KEY")
groq_client = groq.Groq(api_key=groq_api_key)


def analyze_logs(log_text):
    if "unauthorized" in log_text:
        return f"Suspicious log found: {log_text}"
    else:
        return "No threats detected."

def search_cve(query):
    print(f"Searching CVEs for: {query}")
    url = f"https://cve.circl.lu/api/search/{query}"
    try:
        response = requests.get(url)
        results = response.json()
        if results and "results" in results and len(results["results"]) > 0:
            top_3 = results["results"][:3]
            formatted = "\n".join(
                [f"{item['id']}: {item.get('summary', 'No summary')}" for item in top_3]
            )
            return f"Top matching CVEs:\n{formatted}"
        else:
            return "No CVEs found for this query."
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