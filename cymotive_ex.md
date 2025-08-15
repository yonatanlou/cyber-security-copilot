# Cybersecurity Copilot - Technical Documentation

## 1. Solution Design & Architecture {#1-solution-design--architecture}

### Overview

The Cybersecurity Copilot is a GenAI-powered assistant designed to help
security analysts quickly analyze incident reports, generate actionable
mitigation plans, and retrieve similar historical incidents for context.

### Architecture Flow

    ┌─────────────────┐
    │  Raw Incident   │
    │     Report      │
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Input Handler  │◄── Noise Detection
    │   & Cleaner     │    & Preprocessing
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │   LLM Engine    │
    │  (Summarizer)   │◄── System Prompts
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │   Mitigation    │
    │    Generator    │◄── Best Practices DB
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Vector Search  │
    │   (RAG/Hybrid)  │◄── Historical Incidents
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Final Output   │
    │   & Metrics     │
    └─────────────────┘

### Technology Stack

-   **LLM Provider**: OpenAI GPT-4o-mini (primary), with support for
    GPT-4.
-   **Vector Database**: ChromaDb for local development.
-   **Embedding Model**: text-embedding-3-small (OpenAI)
-   **Framework**: LangChain for orchestration
-   **Monitoring**: Custom metrics tracking for tokens, latency, and
    costs


## 2. Prompt Engineering 
### Summarization Prompt
<details>  
<summary> Summarization Prompt</summary>

```
**System Message:**

    You are an expert cybersecurity analyst assistant. Your role is to help security teams quickly understand and respond to incidents.

    TASK: Summarize security incident reports concisely and accurately.

    OUTPUT FORMAT:
    - Executive Summary: 2-3 sentences overview
    - Technical Details: Key technical indicators and artifacts
    - Affected Systems: List of impacted systems/services
    - Attack Vector: Identified attack method if applicable
    - Severity Assessment: Critical/High/Medium/Low with justification
    - Timeline: Key events in chronological order

    Be precise, factual, and highlight the most critical information for rapid response.
```
</details>  

**Design Rationale:**

-   **Structured output** ensures consistency across different incidents
-   **Role definition** (\"expert cybersecurity analyst\") primes the
    model for domain expertise
-   **Explicit sections** prevent important details from being
    overlooked
-   **\"Be precise, factual\"** reduces hallucination risk

### Mitigation Prompt
<details>  
<summary> Mitigation Prompt</summary>
**System Message:**

    You are an expert incident response specialist. Generate actionable mitigation plans for security incidents.

    GUIDELINES:
    1. Prioritize immediate containment actions
    2. Include both short-term and long-term recommendations
    3. Consider business continuity alongside security
    4. Follow industry best practices (NIST, SANS)
    5. Be specific and actionable

    OUTPUT FORMAT:
    ## Immediate Actions (0-4 hours)
    - Specific containment steps
    - Evidence preservation
    - Communication requirements

    ## Short-term Remediation (1-7 days)
    - System hardening
    - Patch management
    - Access control updates

    ## Long-term Improvements (1-4 weeks)
    - Process improvements
    - Security control enhancements
    - Training recommendations

    ## Success Metrics
    - KPIs to measure mitigation effectiveness
</details>  


**NOTE** For all prompts, i decided to add a few exmaples to the user
prompt. Its a good question if it will be better in the system prompt
(Could be an interesting research). My hunch is that the best thing to
do, is to make a more general examples in the system prompts and
generate multiple examples for the user prompt. Then i will randomly
choose examples, and we could analyze what exampels are working the
best. Ive added only one example for the summary prompt for not making
this doc to length

**Few-Shot Example (included in implementation):**

``` python
# For ransomware incidents
example = {
    "incident": "Ransomware detected on file server",
    "response": """
    ## Immediate Actions (0-4 hours)
    - Isolate affected systems from network
    - Identify patient zero and attack vector
    - Activate incident response team
    - Begin forensic imaging of affected systems
    
    ## Short-term Remediation (1-7 days)
    - Restore from clean backups after validation
    - Reset all credentials for affected accounts
    - Deploy EDR to all endpoints
    """
}
```

### Edge Case Handling - Noisy Input

**Specialized Cleaning Prompt:**

    You are a data preprocessing expert for security incidents. You have a vast knowledge of various cyber security incidents.

    TASK: Clean and structure potentially noisy, incomplete, or poorly formatted security incident data.

    INSTRUCTIONS:
    1. Extract all relevant security information
    2. Fill in obvious gaps with [MISSING: field_name]
    3. Standardize technical terms and acronyms
    4. Remove redundant information
    5. Flag any suspicious or potentially corrupted data
    6. Maintain all IoCs (Indicators of Compromise)

    OUTPUT: A cleaned, structured version of the incident report.

**Sample Noisy Input:**

    ===ALERT===ALERT===
    TIME:::    03:45am

    firewall logs showing..... BLOCKED BLOCKED BLOCKED
    IP: 123.456.789.0 (obviously wrong)    port 22 SSH

    admin said virus maybe???? check asap!!!

    CPU 100%%%%%%%%%
    [DATA CORRUPTED] ▪▪▪▪▪

**Cleaned Output:**

    INCIDENT REPORT
    Time: 03:45 AM [MISSING: Date and timezone]

    Firewall Activity:
    - Multiple blocked connection attempts detected
    - Source IP: [INVALID: 123.456.789.0 - notation error]
    - Target Port: 22 (SSH)
    - Status: Blocked by firewall

    Reported Issues:
    - Potential malware infection (unconfirmed)
    - CPU utilization: 100%
    - Data corruption detected in logs

    Priority: HIGH - Requires immediate investigation
    [MISSING: Affected systems, user accounts, additional context]

## 3. Sample Output {#3-sample-output}

### Input Example 1: Brute Force Attack

**Input:**

    INCIDENT REPORT - 2024-01-15 14:23:00 UTC
        
    Multiple failed login attempts detected on production server PROD-WEB-01.
    Source IPs: 192.168.1.105, 10.0.0.23, 45.142.122.76 (external)

    User accounts targeted: admin, root, dbadmin, service_account
    Total attempts: 2,847 over 3 hour period

    Additional observations:
    - Unusual outbound traffic to IP 45.142.122.76 port 4444
    - New scheduled task created: "WindowsUpdate" (suspicious)
    - Memory usage spike at 14:45 UTC
    - PowerShell execution with encoded command detected

    Current status: Server isolated from network
    Severity: HIGH

**Output Summary:**

    SUMMARY:
    Executive Summary: A series of failed login attempts targeting multiple user accounts on production server PROD-WEB-01 were detected, followed by suspicious outbound traffic and the creation of a potentially malicious scheduled task. The server has been isolated from the network to prevent further compromise.

    Technical Details: 2,847 failed login attempts from IPs 192.168.1.105, 10.0.0.23, and external IP 45.142.122.76; outbound traffic to IP 45.142.122.76 on port 4444; suspicious scheduled task "WindowsUpdate" created; PowerShell execution with encoded command observed.

    Affected Systems: PROD-WEB-01 (production server)

    Attack Vector: Brute force login attempts targeting administrative accounts

    Severity Assessment: HIGH - Multiple failed login attempts and suspicious activities indicate a potential compromise, necessitating immediate investigation and response.

    Timeline:
    - 14:23 - Initial detection of failed login attempts
    - 14:45 - Memory usage spike observed
    - 14:45 - Outbound traffic to IP 45.142.122.76 on port 4444 detected
    - 14:45 - Creation of suspicious scheduled task "WindowsUpdate"
    - Current status: Server isolated from network

**Mitigation Plan:**


    MITIGATION PLAN:
    ## Immediate Actions (0-4 hours)
    - **Containment Steps:**
      - Confirm isolation of PROD-WEB-01 from the network to prevent further unauthorized access and lateral movement.
      - Block the identified malicious IP addresses (192.168.1.105, 10.0.0.23, and 45.142.122.76) at the firewall level to prevent further attempts.
      - Disable the suspicious scheduled task "WindowsUpdate" to halt any potential malicious activities.

    - **Evidence Preservation:**
      - Create a forensic image of the PROD-WEB-01 server to preserve the current state for investigation.
      - Collect logs related to authentication attempts, outbound traffic, and scheduled tasks from the server and any relevant network devices.
      - Ensure that all logs are backed up and secured to maintain integrity for future analysis.

    - **Communication Requirements:**
      - Notify the incident response team and relevant stakeholders (IT management, security team, and affected users) about the incident and the immediate actions taken.
      - Prepare a communication plan for informing users about potential impacts and the importance of password changes.

    ## Short-term Remediation (1-7 days)
    - **System Hardening:**
      - Review and enforce strong password policies for all user accounts, especially administrative accounts.
      - Implement account lockout policies to temporarily disable accounts after a specified number of failed login attempts.

    - **Patch Management:**
      - Ensure that all software, especially the operating system and applications on PROD-WEB-01, are updated with the latest security patches.
      - Review and patch any known vulnerabilities related to remote access services.

    - **Access Control Updates:**
      - Review user access privileges and remove any unnecessary administrative privileges.
      - Implement multi-factor authentication (MFA) for all administrative accounts to add an additional layer of security.

    ## Long-term Improvements (1-4 weeks)
    - **Process Improvements:**
      - Develop and implement an incident response plan that includes procedures for detecting and responding to brute force attacks.
      - Establish a regular review process for user accounts and privileges to ensure compliance with the principle of least privilege.

    - **Security Control Enhancements:**
      - Deploy an Intrusion Detection System (IDS) to monitor for unusual login attempts and outbound traffic patterns.
      - Implement logging and monitoring solutions that provide real-time alerts for suspicious activities, including failed login attempts and scheduled task changes.

    - **Training Recommendations:**
      - Conduct security awareness training for all employees, focusing on recognizing phishing attempts and the importance of strong passwords.
      - Provide specialized training for IT staff on incident response procedures and the use of forensic tools.

    ## Success Metrics
    - **KPIs to Measure Mitigation Effectiveness:**
      - Reduction in the number of failed login attempts on production servers by 90% within the next month.
      - Successful implementation of MFA for 100% of administrative accounts within 4 weeks.
      - Completion of security awareness training for all employees within 4 weeks.
      - Zero successful unauthorized access attempts reported in the following quarter.
      - Regular review and updates of access control policies conducted quarterly, with documented changes and improvements.

**Model Used:** GPT-4o-mini **Tokens Used:** \~2183 **Estimated Cost:**
\$0.0007

### Input Example 2: Noisy data incident

**Input:**

    Security Alert: Unusual data transfer detected
    Date: 2024-12-10
    System: Database server DB-PROD-03

    Large data export to external cloud storage detected.
    - 47GB transferred to AWS S3 bucket
    - Bucket name: temp-backup-2024
    - Transfer initiated by user: contractor_john
    - Time: 02:30 AM local time
    - User's normal hours: 9 AM - 5 PM

    User account shows VPN connection from unusual location: Russia
    Normal location: San Francisco, USA

**Cleaned output:**


    CLEANED OUTPUT:
    **Incident Report**

    **Incident Time:** 03:45 AM

    **Incident Type:** Firewall Block

    **Details:**
    - **Firewall Logs:** Blocked access attempts
    - **Source IP Address:** 123.456.789.0 [MISSING: VALID_IP_ADDRESS]
    - **Port:** 22 (SSH)
    - **Potential Threat:** Virus suspected [MISSING: THREAT_DETAILS]
    - **CPU Usage:** 100% [MISSING: CPU_USAGE_DETAILS]
    - **Data Status:** [DATA CORRUPTED] [FLAGGED: DATA_CORRUPTION]

    **Actions Taken:**
    - Password changed already [MISSING: PASSWORD_CHANGE_DETAILS]

    **Urgency Level:** High

    **Additional Notes:**
    - Admin requested immediate assistance.

    **Indicators of Compromise (IoCs):**
    - Source IP: 123.456.789.0
    - Port: 22 (SSH)

    **Recommendations:**
    - Verify the validity of the source IP address.
    - Investigate potential virus presence.
    - Monitor CPU usage for anomalies.
    - Review password change logs for unauthorized access.

**Output Summary:**

    SUMMARY:
    Executive Summary: A high urgency incident was detected involving multiple blocked SSH access attempts from a suspicious IP address, leading to 100% CPU usage and flagged data corruption. Immediate actions included changing passwords and requesting further investigation into potential virus threats.

    Technical Details: Blocked access attempts from source IP 123.456.789.0 on port 22 (SSH), 100% CPU usage observed, data corruption flagged.

    Affected Systems: Affected system(s) with SSH access (specific system not identified).

    Attack Vector: Unauthorized SSH access attempts potentially linked to a virus.

    Severity Assessment: HIGH - High CPU usage and data corruption indicate a serious threat, requiring immediate investigation and remediation.

    Timeline:
    - 03:45 AM - Firewall logs show blocked SSH access attempts from 123.456.789.0
    - Immediate - CPU usage spikes to 100%, data corruption flagged
    - Immediate - Passwords changed, admin requests assistance for further investigation

**Mitigation Plan:**

    ## Immediate Actions (0-4 hours)
    - **Containment Steps:**
      - Isolate affected systems from the network to prevent lateral movement and further data corruption.
      - Block the suspicious IP address (123.456.789.0) at the firewall level to prevent any further access attempts.
      - Disable SSH access on affected systems temporarily until a full investigation can be conducted.

    - **Evidence Preservation:**
      - Collect and secure logs from the firewall, SSH access attempts, and system performance metrics (CPU usage, memory usage).
      - Create a forensic image of the affected systems to preserve the current state for further analysis.
      - Document all actions taken during the incident response for future reference and compliance.

    - **Communication Requirements:**
      - Notify the incident response team and relevant stakeholders (IT, management, legal) about the incident and actions taken.
      - Prepare a communication plan for informing affected users about potential data loss and ongoing investigations.

    ## Short-term Remediation (1-7 days)
    - **System Hardening:**
      - Review and strengthen SSH configurations, including disabling root login, enforcing key-based authentication, and changing the default SSH port if applicable.
      - Implement fail2ban or similar tools to limit the number of failed login attempts and block offending IP addresses.

    - **Patch Management:**
      - Conduct a vulnerability assessment on the affected systems and apply necessary patches to the operating system, SSH service, and any other relevant software.
      - Ensure that all systems have the latest security updates installed to mitigate known vulnerabilities.

    - **Access Control Updates:**
      - Review user accounts with SSH access and remove any unnecessary or inactive accounts.
      - Implement role-based access control (RBAC) to ensure that only authorized personnel have SSH access to critical systems.

    ## Long-term Improvements (1-4 weeks)
    - **Process Improvements:**
      - Develop and implement an incident response plan that includes specific procedures for handling unauthorized access attempts and data corruption incidents.
      - Establish a regular review process for firewall rules and access controls to ensure they are up-to-date and effective.

    - **Security Control Enhancements:**
      - Deploy an Intrusion Detection System (IDS) or Intrusion Prevention System (IPS) to monitor for suspicious activity and provide real-time alerts.
      - Implement multi-factor authentication (MFA) for all remote access services, including SSH, to add an additional layer of security.

    - **Training Recommendations:**
      - Conduct security awareness training for all employees, focusing on recognizing phishing attempts and the importance of strong password practices.
      - Provide specialized training for system administrators on secure SSH configurations and incident response procedures.

    ## Success Metrics
    - **KPIs to Measure Mitigation Effectiveness:**
      - Reduction in the number of blocked SSH access attempts over a defined period (e.g., monthly).
      - Decrease in CPU usage spikes and incidents of data corruption reported in the following months.
      - Percentage of systems compliant with updated security configurations and patch management policies.
      - Number of employees completing security awareness training and their subsequent performance in phishing simulations.
      - Time taken to detect and respond to future incidents, aiming for a reduction in response time compared to this incident.

Tokens used: 2114 Estimated cost: \$0.0007
## 4. Working Prototype {#4-working-prototype}

The core implementation includes:

``` python
# Key components implemented:

1. CybersecurityCopilot class
   - summarize_incident(): Generate structured summaries
   - suggest_mitigation(): Create actionable response plans
   - handle_noisy_input(): Clean malformed reports
   - analyze_incident(): Complete pipeline

2. Helper functions
   - _is_noisy(): Detect poor quality input
   - _estimate_cost(): Calculate API costs

3. Error handling and fallbacks

# Usage:
copilot = CybersecurityCopilot(model="gpt-4o-mini")
result = copilot.analyze_incident(incident_text)
```

``` python


import os
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import hashlib

import dotenv
from openai import OpenAI

dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY", OPENAI_API_KEY))

```

``` python
@dataclass
class SecurityIncident:
    """Data structure for security incidents"""
    id: str
    timestamp: str
    title: str
    description: str
    severity: str
    category: str
    raw_text: Optional[str] = None

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'category': self.category
        }

class CybersecurityCopilot:
    """Main copilot class for incident analysis and response"""

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.3):
        self.model = model
        self.temperature = temperature

    def summarize_incident(self, incident_text: str) -> Dict[str, str]:
        """
        Summarize a security incident report
        """
        system_prompt = """You are an expert cybersecurity analyst assistant. Your role is to help security teams quickly understand and respond to incidents.

TASK: Summarize security incident reports concisely and accurately.

OUTPUT FORMAT:
- Executive Summary: 2-3 sentences overview
- Technical Details: Key technical indicators and artifacts
- Affected Systems: List of impacted systems/services
- Attack Vector: Identified attack method if applicable
- Severity Assessment: Critical/High/Medium/Low with justification
- Timeline: Key events in chronological order

Be precise, factual, and highlight the most critical information for rapid response."""

        user_prompt = f"""Here are examples of how to summarize security incidents:

EXAMPLE 1:
Input: "At 3:45 AM, monitoring detected unusual network traffic from server WEB-01 to external IP 45.67.89.123. Investigation revealed a PHP webshell (shell.php) uploaded through unpatched WordPress plugin. Attacker executed commands to dump database credentials. 50GB of customer data was compressed and staged for exfiltration. Server immediately isolated."

Output:
Executive Summary: Web server compromised via vulnerable WordPress plugin leading to webshell installation and attempted data exfiltration of 50GB customer data. Server has been isolated pending investigation.

Technical Details: PHP webshell (shell.php), external C2 IP 45.67.89.123, database credential dumping, data compression and staging activities detected.

Affected Systems: WEB-01 (primary), Database servers (credentials compromised)

Attack Vector: Exploitation of unpatched WordPress plugin vulnerability

Severity Assessment: CRITICAL - Customer data breach with active exfiltration attempt and database credential compromise

Timeline:
- 03:45 - Unusual outbound traffic detected
- 03:46-04:00 - Investigation reveals webshell and data staging
- 04:00 - Server isolation completed

EXAMPLE 2:
Input: "Multiple failed RDP login attempts from IP range 192.168.45.0/24 targeting administrator and backup_admin accounts on DC-01 and DC-02. Over 10,000 attempts in 2 hours. Followed by successful login to backup_admin. New user 'svc_update' created with domain admin rights. Mimikatz artifacts found in C:\\Windows\\Temp."

Output:
Executive Summary: Successful brute force attack on domain controllers via RDP, resulting in domain admin compromise. Attacker created persistence through new privileged account and deployed credential harvesting tools.

Technical Details: 10,000+ RDP attempts from 192.168.45.0/24, Mimikatz deployment in C:\\Windows\\Temp, new user 'svc_update' with domain admin privileges

Affected Systems: DC-01, DC-02 (Domain Controllers), potentially entire Active Directory domain

Attack Vector: RDP brute force attack targeting administrative accounts

Severity Assessment: CRITICAL - Domain admin compromise with credential harvesting capabilities poses risk to entire infrastructure

Timeline:
- Hour 0-2: 10,000+ failed RDP attempts
- Hour 2: Successful backup_admin compromise
- Hour 2-3: Privilege escalation and Mimikatz deployment

NOW, summarize the following security incident report using the same format:

{incident_text}

Provide a structured summary following the specified format."""

        try:
            response = client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )

            summary = response.choices[0].message.content
            tokens_used = response.usage.total_tokens

            return {
                "summary": summary,
                "tokens_used": tokens_used,
                "model": self.model
            }
        except Exception as e:
            return {
                "error": f"Failed to generate summary: {str(e)}",
                "summary": None
            }

    def suggest_mitigation(self, incident_summary: str, incident_type: str = None) -> Dict[str, str]:
        """
        Suggest mitigation strategies based on incident summary
        """
        system_prompt = """You are an expert incident response specialist. Generate actionable mitigation plans for security incidents.

GUIDELINES:
1. Prioritize immediate containment actions
2. Include both short-term and long-term recommendations
3. Consider business continuity alongside security
4. Follow industry best practices (NIST, SANS)
5. Be specific and actionable

OUTPUT FORMAT:
## Immediate Actions (0-4 hours)
- Specific containment steps
- Evidence preservation
- Communication requirements

## Short-term Remediation (1-7 days)
- System hardening
- Patch management
- Access control updates

## Long-term Improvements (1-4 weeks)
- Process improvements
- Security control enhancements
- Training recommendations

## Success Metrics
- KPIs to measure mitigation effectiveness"""

        # Enhanced prompt with few-shot example for better results
        user_prompt = f"""Based on this incident summary, provide a comprehensive mitigation plan:

{incident_summary}

{f"Incident Type: {incident_type}" if incident_type else ""}

Consider the severity, affected systems, and potential for lateral movement. Provide specific, actionable steps."""

        try:
            response = client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )

            mitigation_plan = response.choices[0].message.content
            tokens_used = response.usage.total_tokens

            return {
                "mitigation_plan": mitigation_plan,
                "tokens_used": tokens_used,
                "model": self.model
            }
        except Exception as e:
            return {
                "error": f"Failed to generate mitigation plan: {str(e)}",
                "mitigation_plan": None
            }

    def handle_noisy_input(self, raw_text: str) -> str:
        """
        Clean and structure noisy or incomplete incident reports
        """
        system_prompt = """You are a data preprocessing expert for security incidents. You have a vast knowledge of various cyber security incidents.

TASK: Clean and structure potentially noisy, incomplete, or poorly formatted security incident data.

INSTRUCTIONS:
1. Extract all relevant security information
2. Fill in obvious gaps with [MISSING: field_name]
3. Standardize technical terms and acronyms
4. Remove redundant information
5. Flag any suspicious or potentially corrupted data
6. Maintain all IoCs (Indicators of Compromise)

OUTPUT: A cleaned, structured version of the incident report."""

        user_prompt = f"""Clean and structure this potentially noisy incident report:

{raw_text}

Preserve all security-relevant information while improving clarity."""

        try:
            response = client.chat.completions.create(
                model=self.model,
                temperature=0.1,  # Lower temperature for cleaning tasks
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )

            return response.choices[0].message.content
        except Exception as e:
            return f"Error cleaning input: {str(e)}\nOriginal text: {raw_text}"

    def analyze_incident(self, incident_text: str, include_mitigation: bool = True) -> Dict:
        """
        Complete incident analysis pipeline
        """
        result = {
            "timestamp": datetime.now().isoformat(),
            "input_length": len(incident_text)
        }

        # Step 1: Clean input if needed
        if self._is_noisy(incident_text):
            cleaned_text = self.handle_noisy_input(incident_text)
            result["cleaned_input"] = cleaned_text
            incident_text = cleaned_text

        # Step 2: Generate summary
        summary_result = self.summarize_incident(incident_text)
        result["summary"] = summary_result

        # Step 3: Generate mitigation plan if requested
        if include_mitigation and summary_result.get("summary"):
            mitigation_result = self.suggest_mitigation(summary_result["summary"])
            result["mitigation"] = mitigation_result

        # Calculate total tokens and estimated cost
        total_tokens = (
            summary_result.get("tokens_used", 0) +
            result.get("mitigation", {}).get("tokens_used", 0)
        )
        result["total_tokens"] = total_tokens
        result["estimated_cost"] = self._estimate_cost(total_tokens)

        return result

    def _is_noisy(self, text: str) -> bool:
        """
        Detect if input text appears noisy or poorly formatted
        (in production env, I will probably implement some encoder based classifier or LLM based)
        """
        indicators = [
            len(text.split('\n')) > 20,  # Too many line breaks
            text.count('===') > 3,  # Excessive separators
            text.count('   ') > 10,  # Multiple spaces
            any(char in text for char in ['�', '□', '▪']),  # Encoding issues
            text.upper() == text and len(text) > 100,  # All caps
        ]
        return sum(indicators) >= 2

    def _estimate_cost(self, tokens: int) -> float:
        """
        Estimate cost based on token usage (GPT-4 pricing as example)
        """
        # Approximate pricing per 1K tokens (adjust based on your model)
        pricing = {
            "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
            "gpt-4": {"input": 0.03, "output": 0.06},
            "gpt-5-nano": {"input": 0.005, "output": 0.4}
        }

        model_pricing = pricing.get(self.model, None)
        # Rough estimate: 60% input, 40% output
        estimated_cost = (tokens * 0.6 * model_pricing["input"] +
                         tokens * 0.4 * model_pricing["output"]) / 1000

        return round(estimated_cost, 4)


```

``` python
# Example usage and testing
def demo_copilot():
    """Demonstrate the copilot functionality"""

    # Initialize copilot
    copilot = CybersecurityCopilot(model="gpt-4o-mini")

    # Sample incident report
    sample_incident = """
    INCIDENT REPORT - 2024-01-15 14:23:00 UTC

    Multiple failed login attempts detected on production server PROD-WEB-01.
    Source IPs: 192.168.1.105, 10.0.0.23, 45.142.122.76 (external)

    User accounts targeted: admin, root, dbadmin, service_account
    Total attempts: 2,847 over 3 hour period

    Additional observations:
    - Unusual outbound traffic to IP 45.142.122.76 port 4444
    - New scheduled task created: "WindowsUpdate" (suspicious)
    - Memory usage spike at 14:45 UTC
    - PowerShell execution with encoded command detected

    Current status: Server isolated from network
    Severity: HIGH
    """

    # Noisy incident example
    noisy_incident = """
    ===ALERT===ALERT===
    TIME:::    03:45am

    firewall logs showing..... BLOCKED BLOCKED BLOCKED
    IP: 123.456.789.0 (obviously wrong)    port 22 SSH

    admin said virus maybe???? check asap!!!

    CPU 100%%%%%%%%%
    [DATA CORRUPTED] ▪▪▪▪▪

    need help urgent    password changed already

    ===END===
    """

    print("=" * 60)
    print("CYBERSECURITY COPILOT DEMO")
    print("=" * 60)

    # Test with clean incident
    print("\n1. ANALYZING CLEAN INCIDENT REPORT:")
    print("-" * 40)
    result = copilot.analyze_incident(sample_incident)

    if result.get("summary", {}).get("summary"):
        print("\nSUMMARY:")
        print(result["summary"]["summary"])

    if result.get("mitigation", {}).get("mitigation_plan"):
        print("\nMITIGATION PLAN:")
        print(result["mitigation"]["mitigation_plan"])

    print(f"\nTokens used: {result.get('total_tokens', 0)}")
    print(f"Estimated cost: ${result.get('estimated_cost', 0)}")

    # Test with noisy incident
    print("\n" + "=" * 60)
    print("2. HANDLING NOISY INPUT:")
    print("-" * 40)
    cleaned = copilot.handle_noisy_input(noisy_incident)
    print("CLEANED OUTPUT:")
    print(cleaned)

    print("\n" + "=" * 60)
    print("3. ANALYZING CLEANED INCIDENT REPORT:")
    print("-" * 40)
    result = copilot.analyze_incident(cleaned)

    if result.get("summary", {}).get("summary"):
        print("\nSUMMARY:")
        print(result["summary"]["summary"])

    if result.get("mitigation", {}).get("mitigation_plan"):
        print("\nMITIGATION PLAN:")
        print(result["mitigation"]["mitigation_plan"])

    print(f"\nTokens used: {result.get('total_tokens', 0)}")
    print(f"Estimated cost: ${result.get('estimated_cost', 0)}")

    return copilot, result




```

``` python
copilot, results = demo_copilot()
```
<details>  
<summary> Demo Copilot: </summary>
```

    ============================================================
    CYBERSECURITY COPILOT DEMO
    ============================================================

    1. ANALYZING CLEAN INCIDENT REPORT:
    ----------------------------------------

    SUMMARY:
    Executive Summary: Multiple failed login attempts targeted critical accounts on production server PROD-WEB-01, followed by suspicious activity including outbound traffic and unauthorized scheduled task creation. The server has been isolated to prevent further compromise.

    Technical Details: 2,847 login attempts from IPs 192.168.1.105, 10.0.0.23, and external IP 45.142.122.76; unusual outbound traffic to IP 45.142.122.76 on port 4444; PowerShell execution with encoded command; new scheduled task "WindowsUpdate" created.

    Affected Systems: PROD-WEB-01 (primary)

    Attack Vector: Brute force login attempts targeting admin-level accounts

    Severity Assessment: HIGH - Significant risk due to multiple failed login attempts on critical accounts and potential unauthorized access indicated by suspicious outbound traffic and task creation.

    Timeline:
    - 14:23 - Multiple failed login attempts detected
    - 14:45 - Memory usage spike observed
    - 14:45 - Outbound traffic to IP 45.142.122.76 on port 4444 detected
    - 14:45 - PowerShell execution with encoded command detected
    - 14:50 - New scheduled task "WindowsUpdate" created
    - 15:00 - Server isolation completed

    MITIGATION PLAN:
    ## Immediate Actions (0-4 hours)
    - **Containment Steps:**
      - Confirm isolation of PROD-WEB-01 from the network to prevent further unauthorized access.
      - Block all traffic from the identified suspicious IP addresses (192.168.1.105, 10.0.0.23, and 45.142.122.76) at the firewall level.
      - Disable all accounts that experienced failed login attempts, especially admin-level accounts.

    - **Evidence Preservation:**
      - Take a forensic image of PROD-WEB-01 to preserve the current state, including logs, memory, and disk contents.
      - Collect and secure logs from the firewall, intrusion detection systems, and server logs to analyze the attack vector and timeline.
      - Document all actions taken during the incident response for future reference.

    - **Communication Requirements:**
      - Notify the incident response team and relevant stakeholders (IT management, security team) about the incident and containment measures.
      - Prepare a communication plan for affected users and departments, ensuring they are aware of the incident and any potential impacts.

    ## Short-term Remediation (1-7 days)
    - **System Hardening:**
      - Review and enforce password policies, ensuring complexity and expiration requirements are met.
      - Implement account lockout policies to prevent brute force attacks.
      - Disable unnecessary services and ports on PROD-WEB-01 to minimize attack surfaces.

    - **Patch Management:**
      - Ensure that all software, including the operating system and applications on PROD-WEB-01, is up to date with the latest security patches.
      - Review and apply any critical patches related to known vulnerabilities that could have been exploited.

    - **Access Control Updates:**
      - Review user access permissions and roles, ensuring the principle of least privilege is enforced.
      - Implement multi-factor authentication (MFA) for all critical accounts to add an additional layer of security.

    ## Long-term Improvements (1-4 weeks)
    - **Process Improvements:**
      - Develop and implement an incident response plan that includes specific steps for handling brute force attacks and suspicious activity.
      - Establish a regular review process for security logs and alerts to identify potential threats proactively.

    - **Security Control Enhancements:**
      - Deploy an intrusion detection/prevention system (IDS/IPS) to monitor for unusual activities and automate responses to potential threats.
      - Implement a centralized logging solution to aggregate logs from all critical systems for better visibility and analysis.

    - **Training Recommendations:**
      - Conduct security awareness training for all employees, focusing on recognizing phishing attempts and the importance of strong password practices.
      - Provide specialized training for IT staff on incident response, threat hunting, and forensic analysis.

    ## Success Metrics
    - **KPIs to Measure Mitigation Effectiveness:**
      - Reduction in the number of failed login attempts by 90% within the next month.
      - Time to detect and respond to suspicious activities reduced to under 30 minutes.
      - Completion of security awareness training for 100% of employees within the next quarter.
      - Implementation of multi-factor authentication across 100% of critical accounts within 4 weeks.
      - Regular audits of user access permissions with a compliance rate of 100% to the principle of least privilege.

    Tokens used: 2221
    Estimated cost: $0.0007

    ============================================================
    2. HANDLING NOISY INPUT:
    ----------------------------------------
    CLEANED OUTPUT:
    **Incident Report**

    **Incident Time:** 03:45 AM

    **Incident Type:** Firewall Block

    **Details:**
    - **Firewall Logs:** Blocked access attempts
    - **Source IP Address:** 123.456.789.0 [MISSING: VALID_IP_ADDRESS]
    - **Port:** 22 (SSH)
    - **Potential Threat:** Virus suspected [MISSING: THREAT_DETAILS]
    - **CPU Usage:** 100% [MISSING: CPU_USAGE_DETAILS]
    - **Data Status:** [DATA CORRUPTED] [FLAGGED: DATA_CORRUPTION]

    **Actions Taken:**
    - Password changed already [MISSING: PASSWORD_CHANGE_DETAILS]

    **Urgency Level:** High

    **Additional Notes:**
    - Admin requested immediate assistance.

    **Indicators of Compromise (IoCs):**
    - Source IP: 123.456.789.0
    - Port: 22 (SSH)

    **Recommendations:**
    - Verify the validity of the source IP address.
    - Investigate potential virus presence.
    - Monitor CPU usage for anomalies.
    - Review password change logs for unauthorized access. 

    **End of Report**

    ============================================================
    3. ANALYZING CLEANED INCIDENT REPORT:
    ----------------------------------------

    SUMMARY:
    Executive Summary: A high urgency incident was detected involving multiple blocked SSH access attempts from a suspicious IP address, leading to 100% CPU usage and flagged data corruption. Immediate actions included changing passwords and requesting further investigation into potential virus threats.

    Technical Details: Blocked access attempts from source IP 123.456.789.0 on port 22 (SSH), 100% CPU usage observed, data corruption flagged.

    Affected Systems: Affected system(s) with SSH access (specific system not identified).

    Attack Vector: Unauthorized SSH access attempts potentially linked to a virus.

    Severity Assessment: HIGH - High CPU usage and data corruption indicate a serious threat, requiring immediate investigation and remediation.

    Timeline:
    - 03:45 AM - Firewall logs show blocked SSH access attempts from 123.456.789.0
    - Immediate - CPU usage spikes to 100%, data corruption flagged
    - Immediate - Passwords changed, admin requests assistance for further investigation

    MITIGATION PLAN:
    ## Immediate Actions (0-4 hours)
    - **Containment Steps:**
      - Isolate affected systems from the network to prevent lateral movement and further data corruption.
      - Block the suspicious IP address (123.456.789.0) at the firewall level to prevent any further access attempts.
      - Disable SSH access on affected systems temporarily until a full investigation can be conducted.

    - **Evidence Preservation:**
      - Collect and secure logs from the firewall, SSH access attempts, and system performance metrics (CPU usage, memory usage).
      - Create a forensic image of the affected systems to preserve the current state for further analysis.
      - Document all actions taken during the incident response for future reference and compliance.

    - **Communication Requirements:**
      - Notify the incident response team and relevant stakeholders (IT, management, legal) about the incident and actions taken.
      - Prepare a communication plan for informing affected users about potential data loss and ongoing investigations.

    ## Short-term Remediation (1-7 days)
    - **System Hardening:**
      - Review and strengthen SSH configurations, including disabling root login, enforcing key-based authentication, and changing the default SSH port if applicable.
      - Implement fail2ban or similar tools to limit the number of failed login attempts and block offending IP addresses.

    - **Patch Management:**
      - Conduct a vulnerability assessment on the affected systems and apply necessary patches to the operating system, SSH service, and any other relevant software.
      - Ensure that all systems have the latest security updates installed to mitigate known vulnerabilities.

    - **Access Control Updates:**
      - Review user accounts with SSH access and remove any unnecessary or inactive accounts.
      - Implement role-based access control (RBAC) to ensure that only authorized personnel have SSH access to critical systems.

    ## Long-term Improvements (1-4 weeks)
    - **Process Improvements:**
      - Develop and implement an incident response plan that includes specific procedures for handling unauthorized access attempts and data corruption incidents.
      - Establish a regular review process for firewall rules and access controls to ensure they are up-to-date and effective.

    - **Security Control Enhancements:**
      - Deploy an Intrusion Detection System (IDS) or Intrusion Prevention System (IPS) to monitor for suspicious activity and provide real-time alerts.
      - Implement multi-factor authentication (MFA) for all remote access services, including SSH, to add an additional layer of security.

    - **Training Recommendations:**
      - Conduct security awareness training for all employees, focusing on recognizing phishing attempts and the importance of strong password practices.
      - Provide specialized training for system administrators on secure SSH configurations and incident response procedures.

    ## Success Metrics
    - **KPIs to Measure Mitigation Effectiveness:**
      - Reduction in the number of blocked SSH access attempts over a defined period (e.g., monthly).
      - Decrease in CPU usage spikes and incidents of data corruption reported in the following months.
      - Percentage of systems compliant with updated security configurations and patch management policies.
      - Number of employees completing security awareness training and their subsequent performance in phishing simulations.
      - Time taken to detect and respond to future incidents, aiming for a reduction in response time compared to this incident.

    Tokens used: 2114
    Estimated cost: $0.0007
```
</details>  
## 5. Retrieval Pipeline (RAG Component) {#5-retrieval-pipeline-rag-component}

### Implementation Overview

The RAG component implements an intelligent search system combining
semantic search with metadata filtering using LangChain\'s self-query
retriever for natural language understanding.

### Architecture

    ┌─────────────────────┐
    │   Natural Language  │
    │      Query Input    │
    └──────────┬──────────┘
               │
         ┌─────▼─────┐
         │   Query   │
         │Constructor│
         │   (LLM)   │
         └─────┬─────┘
               │
         ┌─────▼─────┐
         │Structured │
         │   Query   │
         └─────┬─────┘
               │
         ┌─────┴─────┐
         │           │
         ▼           ▼
    ┌─────────┐ ┌─────────┐
    │Semantic │ │Metadata │
    │ Search  │ │Filtering│
    │(Chroma) │ │ (Self-  │
    │         │ │ Query)  │
    └────┬────┘ └────┬────┘
         │           │
         └─────┬─────┘
               ▼
       ┌──────────────┐
       │Combined      │
       │Results       │
       └──────┬───────┘
              ▼
       ┌──────────────┐
       │ Top-K Results│
       └──────────────┘

### Key Components

#### 1. Vector Search Engine {#1-vector-search-engine}

``` python
Components:
    - Chroma vector database for semantic similarity
    - OpenAI text-embedding-ada-002 for embeddings
    - Self-query retriever for intelligent query parsing
    - Custom query constructor with LangChain
```

#### 2. Incident Knowledge Base {#2-incident-knowledge-base}

**15 Pre-loaded Security Incidents covering:**

-   SQL Injection attacks
-   Brute force attempts (SSH, RDP)
-   Phishing campaigns
-   Ransomware encryption attempts
-   Data exfiltration (DNS tunneling)
-   Privilege escalation
-   DDoS attacks
-   Insider threats
-   Zero-day exploits
-   Cryptomining malware
-   API key exposures
-   Supply chain attacks
-   Password spraying
-   Cross-site scripting (XSS)

Each incident contains:

-   Unique identifier (INC-XXX)
-   Title and detailed description
-   Severity level (CRITICAL/HIGH/MEDIUM/LOW)
-   Category (attack type classification)
-   Timestamp (ISO format)
-   Year (extracted for temporal filtering)

#### 3. Search Methods {#3-search-methods}

**Semantic Search:**

-   Uses OpenAI embeddings via LangChain
-   Vector similarity search in Chroma
-   Best for: Conceptual queries, attack patterns, behavioral
    descriptions

**Metadata Filtering:**

-   Automatic extraction from natural language
-   Supports filters on: severity, category, year
-   Logical operators: AND, OR, EQ, GT, LT, etc.
-   Best for: Specific criteria, temporal queries, severity-based
    searches

**Self-Query Retrieval:**

-   Natural language to structured query translation
-   Combines semantic search with metadata filters
-   Example: \"Show me brute force attacks with high severity in 2024\"
    -   Semantic: searches for \"brute force attacks\"
    -   Filter: `and(eq("severity", "HIGH"), eq("year", 2024))`

### Query Constructor Details

The system uses a custom prompt template that:

1.  **Parses** natural language into structured components
2.  **Separates** semantic content from metadata filters
3.  **Generates** proper filter expressions
4.  **Handles** complex logical operations

Example structured query format:

``` json
{
    "query": "brute force attacks",
    "filter": "and(eq(\"severity\", \"HIGH\"), eq(\"year\", 2024))"
}
```

### Supported Metadata Fields

| Field    | Type    | Description            | Example Values                                   |
|----------|---------|------------------------|--------------------------------------------------|
| severity | string  | Incident severity level| LOW, MEDIUM, HIGH, CRITICAL                      |
| category | string  | Attack type classification | "Unauthorized Access", "Malware", "Web Application Attack" |
| year     | integer | Year of incident       | 2024, 2023, etc.                                 |


### Usage Example

``` python
# Initialize with OpenAI API key
import os

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# Setup retriever with custom query constructor
retriever, vectorstore, query_constructor = setup_retriever(OPENAI_API_KEY)

# Natural language queries automatically parsed
queries = [
    "Show me brute force attacks with high severity in 2024",
    "Find critical incidents from 2024",
    "What ransomware incidents do we have?",
    "Show me all unauthorized access attempts",
    "Find malware with high or critical severity"
]

# Search for incidents
results = search_incidents(query, retriever, k=2)
```

### Query Examples and Expected Behavior

  ---------------------------------------------------------------------------------------------
  Query          Semantic Search              Metadata Filter
  -------------- ---------------------------- -------------------------------------------------
  \"brute force  \"brute force\"              `and(eq("severity", "HIGH"), eq("year", 2024))`
  high severity                               
  2024\"                                      

  \"critical     \"ransomware\"               `eq("severity", "CRITICAL")`
  ransomware\"                                

  \"2024 malware \"malware incidents\"        `eq("year", 2024)`
  incidents\"                                 

  \"phishing     \"phishing attacks\"         NO_FILTER
  attacks\"                                   
  ---------------------------------------------------------------------------------------------

### Scaling Considerations

**Current Implementation (PoC):**

-   In-memory Chroma database
-   15 sample incidents
-   Single-threaded operation
-   Local vector storage

**Production Scaling Recommendations:**

-   Migrate to persistent Chroma with disk storage
-   Implement Chroma client-server architecture for distributed access
-   Add Redis caching layer for frequent queries
-   Use batch embedding generation for new incidents
-   Implement async query processing
-   Consider Pinecone/Weaviate for larger scale (100K+ incidents)
-   Add query result caching with TTL


``` python
!pip install langchain langchain-openai langchain-chroma langchain-community chromadb openai lark
```

``` python
"""
Cybersecurity Copilot - Simple RAG Pipeline with Semantic Search and Metadata Filtering
"""


import json
from datetime import datetime
from typing import List, Dict, Any
import os

import dotenv

from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from langchain.schema import Document
from langchain.chains.query_constructor.base import AttributeInfo
from langchain.retrievers.self_query.base import SelfQueryRetriever
from langchain_openai import ChatOpenAI

dotenv.load_dotenv()
```
<details>  
<summary> INCIDENTS_DATA</summary>

``` python
# Sample incident data
INCIDENTS_DATA = [
    {
        "id": "INC-001",
        "title": "SQL Injection Attack on Web Application",
        "description": "Multiple SQL injection attempts detected on login endpoint. Attacker tried to bypass authentication using various payloads. WAF blocked most attempts but one succeeded.",
        "severity": "HIGH",
        "timestamp": "2024-01-10T08:15:00Z",
        "category": "Web Application Attack"
    },
    {
        "id": "INC-002",
        "title": "Brute Force Attack on SSH Service",
        "description": "Detected 2,847 failed SSH login attempts over 3 hours on port 22. Successful breach followed by backdoor installation. Attacker gained root access and established persistence.",
        "severity": "HIGH",
        "timestamp": "2024-01-15T14:23:00Z",
        "category": "Brute Force"
    },
    {
        "id": "INC-003",
        "title": "Phishing Campaign Targeting Employees",
        "description": "Sophisticated phishing emails mimicking IT department notifications. 12 employees clicked malicious links. Two credentials were compromised before detection.",
        "severity": "MEDIUM",
        "timestamp": "2024-02-01T09:30:00Z",
        "category": "Social Engineering"
    },
    {
        "id": "INC-004",
        "title": "Ransomware Encryption Attempt",
        "description": "WannaCry variant detected attempting to encrypt network shares. EDR solution quarantined the process. No data was encrypted. Isolated infected machine from network.",
        "severity": "CRITICAL",
        "timestamp": "2024-02-15T03:45:00Z",
        "category": "Malware"
    },
    {
        "id": "INC-005",
        "title": "Data Exfiltration via DNS Tunneling",
        "description": "Abnormal DNS query patterns detected. Investigation revealed 2GB of sensitive data transmitted via DNS tunneling to external server. Source was compromised workstation.",
        "severity": "HIGH",
        "timestamp": "2024-03-01T16:20:00Z",
        "category": "Data Breach"
    },
    {
        "id": "INC-006",
        "title": "Privilege Escalation on Linux Server",
        "description": "Attacker exploited CVE-2024-1234 to escalate privileges from www-data to root. Kernel vulnerability allowed local privilege escalation. Patch applied immediately.",
        "severity": "HIGH",
        "timestamp": "2024-03-10T11:00:00Z",
        "category": "System Compromise"
    },
    {
        "id": "INC-007",
        "title": "DDoS Attack on Public Services",
        "description": "Volumetric DDoS attack peaking at 100 Gbps. Multiple botnets involved. CloudFlare mitigation activated. Services remained available with degraded performance.",
        "severity": "MEDIUM",
        "timestamp": "2023-03-20T18:30:00Z",
        "category": "Denial of Service"
    },
    {
        "id": "INC-008",
        "title": "Insider Threat - Unauthorized Data Access",
        "description": "Employee accessed confidential HR records without authorization. Audit logs show systematic download of employee personal information. User account suspended pending investigation.",
        "severity": "HIGH",
        "timestamp": "2019-04-05T13:15:00Z",
        "category": "Insider Threat"
    },
    {
        "id": "INC-009",
        "title": "Zero-Day Exploit in Email Server",
        "description": "Previously unknown vulnerability in Exchange server exploited. Attacker gained remote code execution capabilities. Emergency patch deployed. Full forensic analysis ongoing.",
        "severity": "CRITICAL",
        "timestamp": "2024-04-12T07:00:00Z",
        "category": "Zero-Day Attack"
    },
    {
        "id": "INC-010",
        "title": "Cryptomining Malware on Workstations",
        "description": "Multiple workstations infected with Monero mining malware. High CPU usage reported. Malware spread via infected USB drives. All instances removed and USB ports disabled.",
        "severity": "LOW",
        "timestamp": "2024-04-20T10:45:00Z",
        "category": "Malware"
    },
    {
        "id": "INC-011",
        "title": "API Key Exposure in GitHub Repository",
        "description": "Production API keys found in public GitHub repository. Keys provided access to customer database. Immediately rotated all keys and implemented secret scanning.",
        "severity": "HIGH",
        "timestamp": "2024-05-01T14:00:00Z",
        "category": "Configuration Error"
    },
    {
        "id": "INC-012",
        "title": "Brute Force Attack on RDP Services",
        "description": "Detected 5,000+ failed RDP login attempts from distributed IPs. Attack targeted administrator accounts. Implemented account lockout policy and IP blocking.",
        "severity": "MEDIUM",
        "timestamp": "2024-05-10T22:30:00Z",
        "category": "Unauthorized Access"
    },
    {
        "id": "INC-013",
        "title": "Supply Chain Attack via Third-Party Library",
        "description": "Malicious code discovered in npm package dependency. Package was compromised and included credential stealer. Removed package and audited all dependencies.",
        "severity": "HIGH",
        "timestamp": "1994-05-20T09:00:00Z",
        "category": "Supply Chain Attack"
    },
    {
        "id": "INC-014",
        "title": "Password Spraying Attack",
        "description": "Low and slow password attack using common passwords across multiple accounts. Three accounts compromised before detection. MFA enforcement initiated company-wide.",
        "severity": "MEDIUM",
        "timestamp": "2019-06-01T15:45:00Z",
        "category": "Unauthorized Access"
    },
    {
        "id": "INC-015",
        "title": "Cross-Site Scripting (XSS) in Web Portal",
        "description": "Stored XSS vulnerability found in customer portal comment section. Could execute arbitrary JavaScript in user browsers. Patched immediately, no evidence of exploitation.",
        "severity": "MEDIUM",
        "timestamp": "2023-06-15T11:30:00Z",
        "category": "Web Application Attack"
    }
]

```
</details>  
``` python
def setup_retriever(openai_api_key: str):
    """
    Set up the vector store and self-query retriever for semantic search with metadata filtering
    """

    # Initialize embeddings
    embeddings = OpenAIEmbeddings(openai_api_key=openai_api_key)

    # Prepare documents for vector store
    documents = []
    for incident in INCIDENTS_DATA:
        # Combine title and description for better semantic search
        content = f"{incident['title']}\n{incident['description']}"

        # Extract year from timestamp for easier filtering
        year = datetime.fromisoformat(incident['timestamp'].replace('Z', '+00:00')).year

        # Create metadata
        metadata = {
            "id": incident["id"],
            "severity": incident["severity"],
            "category": incident["category"],
            "year": year,
            "timestamp": incident["timestamp"]
        }

        doc = Document(page_content=content, metadata=metadata)
        documents.append(doc)

    # Create Chroma vector store
    vectorstore = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        collection_name="security_incidents"
    )

    # Define metadata fields for self-query
    metadata_field_info = [
        AttributeInfo(
            name="severity",
            description="The severity level of the incident",
            type="string",
        ),
        AttributeInfo(
            name="category",
            description="The category or type of security incident",
            type="string",
        ),
        AttributeInfo(
            name="year",
            description="The year when the incident occurred",
            type="integer",
        ),
    ]

    # Document description for the LLM
    document_content_description = "Security incident reports containing title and description"

    # Create self-query retriever
    llm = ChatOpenAI(temperature=0, openai_api_key=openai_api_key, model="gpt-4o-mini")

    retriever = SelfQueryRetriever.from_llm(
        llm=llm,
        vectorstore=vectorstore,
        document_contents=document_content_description,
        metadata_field_info=metadata_field_info,
        enable_limit=False,  # Disable limit to avoid parsing issues
        verbose=True  # Set to True to see the generated queries
    )

    return retriever, vectorstore

def search_incidents(query: str, retriever, k: int = 2) -> List[Dict[str, Any]]:
    """
    Search for incidents using natural language query with semantic search and metadata filtering
    """

    # Retrieve relevant documents - using invoke instead of deprecated method
    try:
        docs = retriever.invoke(query)[:k]  # Limit results to k
    except Exception as e:
        print(f"  Warning: Query parsing failed, falling back to similarity search")
        # Fallback to simple similarity search if self-query fails
        docs = retriever.vectorstore.similarity_search(query, k=k)

    # Format results
    results = []
    for doc in docs:
        result = {
            "id": doc.metadata.get("id"),
            "content": doc.page_content,
            "severity": doc.metadata.get("severity"),
            "category": doc.metadata.get("category"),
            "timestamp": doc.metadata.get("timestamp"),
            "relevance_score": getattr(doc, 'score', None)
        }
        results.append(result)

    return results

def main():
    """
    Main function to demonstrate the RAG pipeline
    """

    # Set your OpenAI API key
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "your-api-key-here")

    if OPENAI_API_KEY == "your-api-key-here":
        print("⚠️  Please set your OPENAI_API_KEY environment variable or update the code")
        return

    print("🚀 Initializing Cybersecurity Copilot RAG Pipeline...")
    print("-" * 50)

    # Setup retriever
    retriever, vectorstore = setup_retriever(OPENAI_API_KEY)
    print("✅ Vector store and retriever initialized")
    print(f"📊 Loaded {len(INCIDENTS_DATA)} security incidents")
    print("-" * 50)

    # Example queries to demonstrate capabilities
    test_queries = [
        "Show me brute force attacks with high severity in 2024",
        "Find critical incidents from 2019",
        "What ransomware incidents do we have?",
        "Show me all unauthorized access attempts",
        "Find incidents related to malware with high or critical severity"
    ]

    print("\n🔍 Running example searches:\n")

    for i, query in enumerate(test_queries, 1):
        print(f"\n📌 Query {i}: {query}")
        print("-" * 40)

        try:
            results = search_incidents(query, retriever, k=3)

            if results:
                for j, result in enumerate(results, 1):
                    print(f"\n  Result {j}:")
                    print(f"  ID: {result['id']}")
                    print(f"  Severity: {result['severity']}")
                    print(f"  Category: {result['category']}")
                    print(f"  Timestamp: {result['timestamp']}")
                    print(f"  Summary: {result['content'][:150]}...")
            else:
                print("  No matching incidents found.")

        except Exception as e:
            print(f"  Error: {str(e)}")

    # Interactive mode
    print("\n" + "=" * 50)
    print("💬 Interactive Mode - Enter your queries (type 'quit' to exit)")
    print("=" * 50)


if __name__ == "__main__":
    main()
```

    🚀 Initializing Cybersecurity Copilot RAG Pipeline...
    --------------------------------------------------
    ✅ Vector store and retriever initialized
    📊 Loaded 15 security incidents
    --------------------------------------------------

    🔍 Running example searches:


    📌 Query 1: Show me brute force attacks with high severity in 2024
    ----------------------------------------
      No matching incidents found.

    📌 Query 2: Find critical incidents from 2019
    ----------------------------------------
      No matching incidents found.

    📌 Query 3: What ransomware incidents do we have?
    ----------------------------------------

      Result 1:
      ID: INC-004
      Severity: CRITICAL
      Category: Malware
      Timestamp: 2024-02-15T03:45:00Z
      Summary: Ransomware Encryption Attempt
    WannaCry variant detected attempting to encrypt network shares. EDR solution quarantined the process. No data was encryp...

      Result 2:
      ID: INC-004
      Severity: CRITICAL
      Category: Malware
      Timestamp: 2024-02-15T03:45:00Z
      Summary: Ransomware Encryption Attempt
    WannaCry variant detected attempting to encrypt network shares. EDR solution quarantined the process. No data was encryp...

      Result 3:
      ID: INC-010
      Severity: LOW
      Category: Malware
      Timestamp: 2024-04-20T10:45:00Z
      Summary: Cryptomining Malware on Workstations
    Multiple workstations infected with Monero mining malware. High CPU usage reported. Malware spread via infected U...

    📌 Query 4: Show me all unauthorized access attempts
    ----------------------------------------

      Result 1:
      ID: INC-008
      Severity: HIGH
      Category: Insider Threat
      Timestamp: 2019-04-05T13:15:00Z
      Summary: Insider Threat - Unauthorized Data Access
    Employee accessed confidential HR records without authorization. Audit logs show systematic download of empl...

      Result 2:
      ID: INC-008
      Severity: HIGH
      Category: Insider Threat
      Timestamp: 2019-04-05T13:15:00Z
      Summary: Insider Threat - Unauthorized Data Access
    Employee accessed confidential HR records without authorization. Audit logs show systematic download of empl...

      Result 3:
      ID: INC-001
      Severity: HIGH
      Category: Web Application Attack
      Timestamp: 2024-01-10T08:15:00Z
      Summary: SQL Injection Attack on Web Application
    Multiple SQL injection attempts detected on login endpoint. Attacker tried to bypass authentication using vari...

    📌 Query 5: Find incidents related to malware with high or critical severity
    ----------------------------------------
      No matching incidents found.

    ==================================================
    💬 Interactive Mode - Enter your queries (type 'quit' to exit)
    ==================================================

## 6. Evaluation & Cost Awareness {#6-evaluation--cost-awareness}

### Performance Metrics

**Quality Metrics:**

-   **Accuracy Score**: Compare against human analyst summaries (target:
    \>85%)
-   **Completeness**: % of key IoCs identified (target: \>95%)
-   **False Positive Rate**: Incorrect severity assessments (target:
    \<10%)
-   **Response Relevance**: Mitigation plan applicability score (1-5
    scale)

**Operational Metrics:**

-   **Response Time**: P50 \< 3s, P95 \< 8s
-   **Token Efficiency**: Avg tokens per incident \< 1,500
-   **Cost per Analysis**: \< \$0.005 per incident
-   **Availability**: 99.9% uptime

### Hallucination Risk Mitigation

1.  **Temperature Control**: Low temperature (0.3) for factual tasks
2.  **Structured Prompts**: Explicit output format reduces creative
    interpretation
3.  **Fact Verification**: Cross-reference IoCs with threat intelligence
    feeds
4.  **Confidence Scoring**: Add uncertainty indicators for
    low-confidence outputs

### Cost Estimation

  Component       Tokens/Request   Cost/1K Tokens   Total Cost
  --------------- ---------------- ---------------- ---------------
  Summarization   800              \$0.00015        \$0.00012
  Mitigation      600              \$0.00015        \$0.00009
  RAG Search      200              \$0.00015        \$0.00003
  **Total**       **1,600**        \-               **\$0.00024**

**Monthly projection** (1,000 incidents): \~\$240

### Monitoring Strategy

``` python
# Monitoring implementation
class CopilotMonitor:
    def track_metrics(self, result):
        metrics = {
            "latency": result.processing_time,
            "tokens": result.total_tokens,
            "cost": result.estimated_cost,
            "model": result.model,
            "error_rate": result.errors / result.total,
            "cache_hit_rate": result.cache_hits / result.total
        }
        
        # Alert thresholds
        if metrics["latency"] > 10:
            alert("High latency detected")
        if metrics["error_rate"] > 0.05:
            alert("Error rate exceeding threshold")
            
        return metrics
```

### Performance Optimization

1.  **Caching**: Cache similar incident summaries (30% reduction in API
    calls)
2.  **Batch Processing**: Group similar incidents for efficiency
3.  **Model Selection**: Use GPT-4o-mini for simple incidents, GPT-4 for
    complex
4.  **Prompt Optimization**: Continuously refine prompts based on output
    quality

### Drift Detection

Monitor for:

-   Changes in incident patterns requiring prompt updates
-   Model performance degradation over time
-   New attack vectors not covered by current prompts
-   Feedback loop: Monthly review of low-scored outputs

