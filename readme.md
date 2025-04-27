# AI Cybersecurity Agent (Groq + CVE Scanner)

This project is an AI-powered cybersecurity agent that:
- Analyzes suspicious logs for potential threats
- Cross-checks known vulnerabilities (CVEs)
- Sends alerts to Slack
- Uses **Groq's ultra-fast LLMs** for expert analysis

## How it works

1. Input: A system log or error message
2. Process: 
   - Analyze using **Groq Llama 3-70b** model
   - Search for related vulnerabilities via NVD CVE API
3. Output:
   - Full AI analysis of the potential threat
   - Top related CVEs
   - Slack alert if a critical issue is found

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/ai-threat-hunter.git
cd ai-threat-hunter
pip install -r requirements.txt


## Environment Variables
GROQ_API_KEY=your-groq-api-key-here
SLACK_WEBHOOK_URL=your-slack-webhook-url-here


### Run the Agent 
python threat_agent.py


### Tech Stack
Groq API
NVD CVE Database API
Slack Webhooks
Python 3.10+




