# Vulnerability Assessment & Penetration Testing (VAPT-DVWA)

## 📖Overview
This project documents a structured Vulnerability Assessment and Penetration Testing (VAPT) exercise conducted on Damn Vulnerable Web Application (DVWA). It demonstrates the use of industry-standard tools to identify, validate, and analyze common web application vulnerabilities.

## 🎯Key Focus Areas 
- OWASP Top 10 vulnerability assessment
- Automated scanning and manual validation
- Analysis of exploitability and risk severity
- Remediation recommendations and verification

## 🛠️Technologies
OWASP ZAP, Burp Suite, SQLMap, Web Security Methodologies

## 📝Assessment Overview
| Category | Details |
|--------|--------|
| Target System | Damn Vulnerable Web Application (DVWA) |
| Attacker Environment | Kali Linux |
| Assessment Type | Web Application Vulnerability Assessment |
| Penetration Testing Approach | White Box Testing |
| VAPT Methodology | CompTIA |
| Legal & Compliance | Statements of Work (SOW), Non-Disclosure Agreements (NDA), Rules of Engagement (ROE) |
| Industry Standards | ISO/IEC 27001, NIST Cybersecurity Framework (NIST CSF) |
| Start Date | Wednesday, 19March2025, 11:06:31PM  |
| End Date | Wednesday, 26March2025, 7:31:11PM |

## 🔍Main Focus
This project conducted a comprehensive Vulnerability Assessment (VA) and Penetration Testing (PT) on the Damn Vulnerable Web Application (DVWA), focusing on web application security and the OWASP Top 10 vulnerabilities. The assessment was divided into two parts: VA **(SECTION 2.0)** for identifying potential weaknesses and PT **(SECTION 3.0)** for exploiting critical vulnerabilities such as CSRF and SQLi, with the scope limited to DVWA hosted locally and the attacker environment using Kali Linux. A white box testing approach was applied following CompTIA VAPT methodology to provide structured and repeatable security evaluation.

### SECTION 2.0 -- Vulnerability Assessment
During the Vulnerability Assessment, automated scanning was performed using OWASP ZAP. The assessment included a broad scan across all endpoints, followed by a targeted scan for specific vulnerable pages. Several critical vulnerabilities were discovered, including Reflected Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Injection flaws, Security Misconfiguration, Broken Access Control, Insecure Design, and Software/Data Integrity failures. The VA phase provided a comprehensive view of the security posture, highlighting areas requiring immediate remediation.

<img width="600" alt="image" src="https://github.com/user-attachments/assets/9f95379d-55f8-4d0e-b805-137f59354bcb" />
<img width="600" alt="image" src="https://github.com/user-attachments/assets/3e12badd-c456-4404-80c7-48f8ce38857c" />
<img width="600" alt="image" src="https://github.com/user-attachments/assets/ad47af5b-7222-419c-9cc1-1c1ce8ee9a5e" />
<img width="600" alt="image" src="https://github.com/user-attachments/assets/01a0285d-9830-4acd-bcba-b81ea2c735cb" />
<img width="600" alt="image" src="https://github.com/user-attachments/assets/37a4a5d8-6f6e-4ffa-b56b-6a40fd49e646" />

### SECTION 3.0 -- Penetration Testing
During the Penetration Testing phase, focus was placed on exploiting the two most severe vulnerabilities: CSRF and SQL Injection using Burp Suite and SQLMap. Being a white box test, vulnerabilities were also analyzed through source code review to confirm exploitability. Key examples include a CSRF token exposed in HTML source code and a SQL injection vulnerability allowing extraction of sensitive user information. This section also analyses the impact of each vulnerability exploited.

**Vulnerability 1: CSRF (CSRF token implemented but exposed in HTML source code)**

Password can be modified upon replacing new valid token that can be found in HTML Request.

<img width="600" alt="image" src="https://github.com/user-attachments/assets/a7d7092d-4da8-4aae-aa6e-8bc5b03ec539" />
<img width="600" alt="image" src="https://github.com/user-attachments/assets/9e4c3764-c5e7-4b0c-9bd7-6c46c9b6a840" />
<img width="600" alt="image" src="https://github.com/user-attachments/assets/f621f0cb-d98e-4eff-9d79-768cba362aa2" />

Potential Impact:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/043d0e72-f166-4b2e-84cf-82d034d66b20" />

**Vulnerability 2: SQL Injection**

Password can be extracted in table users.

<img width="600" alt="image" src="https://github.com/user-attachments/assets/1301a5b9-ad0a-41cf-9310-5c5d5abc68df" />

Potential Impact: 

<img width="600" alt="image" src="https://github.com/user-attachments/assets/74755ef5-bddc-499f-838e-6a7e5e227599" />

### SECTION 4.0 -- Countermeasure & Recommendations
Countermeasures and Recommendations were developed for the identified critical vulnerabilities.
<img width="600" alt="image" src="https://github.com/user-attachments/assets/021ef4a0-1642-4f8d-9c40-dad67fd5b61c" />

## 📚References
### Table of Contents
<img width="400" alt="image" src="https://github.com/user-attachments/assets/8ae400ff-a7c6-44ad-8672-49ec5adf5843" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/d2e09d90-632a-44d2-ae82-97d8e0a7c932" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/47c0e116-69e0-4347-abce-e653fb2ea171" />

> Note: This project is based on a university assignment and has been adapted for portfolio purposes.
> All content is sanitized and does not include exploit payloads or sensitive information.

