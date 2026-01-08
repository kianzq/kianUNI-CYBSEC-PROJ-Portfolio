# MalCommandGuard – Malicious Command Detection System

<img width="940" height="182" alt="image" src="https://github.com/user-attachments/assets/392092dd-0262-45b5-9e55-50b1598bcaee" />

## 📖Overview
MalCommandGuard is a **hybrid command-line risk detection system** designed to identify and classify potentially **Malicious, Suspicious, or Benign** commands executed via terminal or scripting environments such as PowerShell, CMD, or Bash. The system overcomes the weaknesses of conventional security types since by applying **rule-based detection**, **Machine Learning (ML)** classification, and **Natural Language Processing (NLP)** used in combination to both augment semantic understanding and threat accuracy. 

Beaides, it stresses on the **use of secure coding**, such as encrypted logging, input checking, sanitization of the environment variables, and regulated file access to **provide integrity of operation and safety of data**. The architecture enables modular capability and thus the **real-time analysis**, **secure history viewing,** and **enriching with AI and threat intelligence** using explainable results. **Risk scoring and the interpretability** improve the detection results as well, so the system becomes not only viable but also transparent to cybersecurity analysts. 

MalCommandGuard can provide efficient command-line based threat monitoring and mitigation in the contemporary computing systems through a thorough comparison of detection approaches and secure-by-design solution.

## 🎯Key Focus Areas
| Functionality | Description |
|--------|--------|
| Hybrid Threat Detection | Combines rule-based, machine learning, and NLP techniques for accurate command risk detection. |
| Command-Based Attack Detection | Identifies malicious, suspicious, and legitimate commands, including obfuscated patterns. |
| Secure Software Engineering | Implements secure coding practices such as input validation, access control, and cryptographic protection. |
| Explainable AI | Provides interpretable risk scores and explanations to support analyst decisions. |
| Operational Security | Ensures secure logging, permission management, environment variable protection, and safe configuration. |
| Modular & Scalable Design | Uses a maintainable architecture that supports extensibility and future enhancements. |
| Analyst-Oriented Usability | Offers a CLI-based interface with clear output and secure log review for operational use. |


## 🛠️Technologies
- Python
- Hybrid Detection Engine Model Training -- ML (RandomForestClassifier), NLP (spaCy, SentenceTransformer), Feature Extraction (TF-IDF Text, Linguistic, Rule-based, Semantic Embeddings , Numeric Features)
- AI Analysis
- Threat Intelligence Souces (VirusTotal, Shodan, AbuseIPDB)
- Secure Logging (Logs Encryption & Decryption, File Permission)

## 📝System Architecture
<img width="1454" height="693" alt="image" src="https://github.com/user-attachments/assets/57a1ed4d-b65e-40df-9d9d-ffae171fedde" />

## 🔍Main Focus
### Command Analysis / File Analysis 
Benign Command:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/780ff989-5ef8-4feb-bc08-ce0adcb1e60e" />

Malicious Command:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/51c4a82f-abd4-4a0e-880a-8fc46e410984" />

---------------------------------------------------------------------------------------------------------

### Advanced Analysis
AI Analysis:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/4528d065-7ef2-463a-97ff-c9b17d7bfb96" />

Threat Intelligence Result:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/d838d414-ae19-4447-8dfd-b36da7445e5c" />
<img width="600" alt="image" src="https://github.com/user-attachments/assets/a9b4be28-b063-40eb-b6e0-3148688afb3c" />

---------------------------------------------------------------------------------------------------------

### Secure Logging (History) with Authentication
Fail to authenticate user:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/91ad084f-3818-4768-8b1b-b7ab8daaea45" />

Authenticated user:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/226dfb1c-0d40-486a-9fe5-8290a9ae7ec7" />

View Specific Log:

<img width="600" alt="image" src="https://github.com/user-attachments/assets/4f079287-05e3-40c8-b430-949fa9a2466d" />

---------------------------------------------------------------------------------------------------------

### Alert Report
<img width="400" alt="image" src="https://github.com/user-attachments/assets/a12884c2-30af-4c75-947e-9d33b1bc9f65" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/a59f959f-5fe0-47d7-8c20-2a05aa6d3b64" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/9fcb6417-c192-4fd7-a3e9-b689d47fdf8d" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/86fd0773-1775-4cfc-922e-c33fcf52c963" />

---------------------------------------------------------------------------------------------------------

### Model Training
**Dataset: cmd_dataset.xlsx**

<img width="600" alt="image" src="https://github.com/user-attachments/assets/0939e566-f177-4adc-bbb9-f523912afdbf" />

**6.1	Data Loading and Preprocessing**

<img width="600" alt="image" src="https://github.com/user-attachments/assets/10b6e7d0-5b20-4748-a9fe-eefb5e190abb" />

**6.2	NLP Processor Initialization**

<img width="600" alt="image" src="https://github.com/user-attachments/assets/55dbad11-a17a-4b57-b446-17bc2d652ee4" />

**6.3	Feature Extraction**

<img width="600" alt="image" src="https://github.com/user-attachments/assets/01298f0e-a0af-46f0-8f2d-64ee4ef4c237" />
<img width="600" alt="image" src="https://github.com/user-attachments/assets/51732bd3-57ce-4bda-822c-93b35d7bfa71" />

**6.4	Model Training and Hyperparameter Optimization**

<img width="600" alt="image" src="https://github.com/user-attachments/assets/97920922-dded-4bc2-9e43-6360bd882da2" />

**6.5	Model Evaluation and Validation**

<img width="600" alt="image" src="https://github.com/user-attachments/assets/73195f36-b3aa-47da-8c25-c905de51e806" />

**Model Training Result**

<img width="400" alt="image" src="https://github.com/user-attachments/assets/78367aec-95ad-49c4-9332-ae9681899eae" />

---------------------------------------------------------------------------------------------------------
## ✅Conclusion
The development of MalCommandGuard provided a strong learning experience in designing a security-centric detection system that integrates rule-based logic, machine learning, and natural language processing to detect modern command-based cyber threats. Through this project, I gained a clear understanding of how hybrid detection architectures improve accuracy, contextual analysis, and resilience against evasive and obfuscated commands compared to single-method approaches.

Beyond detection, the project reinforced a secure-by-design developer mindset, emphasizing the importance of integrating security throughout the software development lifecycle. I applied practical secure coding techniques, including input validation and sanitization, authentication and authorization, secure session handling, cryptographic protection, and secure logging. I also gained hands-on experience in operational security, such as secure environment variable handling, permission management, and safe configuration practices.

Overall, MalCommandGuard enabled me to bridge theory with real-world implementation, combining intelligent threat detection with defensive software engineering principles. The project highlighted the importance of building systems that are not only effective in detecting threats, but also secure, maintainable, explainable, and aligned with real-world cybersecurity requirements.

## 📚 References
<img width="400" alt="image" src="https://github.com/user-attachments/assets/409ba995-9057-487b-9e04-634374d785a5" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/d58c2fd3-5f30-4ae1-81e4-f67b84868920" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/c7f790b1-59de-4a41-96e4-1ff5541ea4e1" />

> Note: This project is based on a university assignment and has been adapted for portfolio purposes. All content is sanitized and does not include exploit payloads or sensitive information. Commands tested are randomly generated and does not include sensitive information.
