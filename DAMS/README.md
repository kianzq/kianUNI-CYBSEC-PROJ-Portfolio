# Distributor Agent Management System (DAMS)

## 📖Overview
This project focuses on secure database design and access control implementation for a distributor management system. It emphasizes applying security best practices during database migration and system hardening to protect sensitive business data.

## 🎯Key Focus Areas
- Role-Based Access Control (RBAC) and authorization matrices
- Row-Level Security (RLS) to restrict data access
- Data protection using hashing, masking, and encryption
- Auditing, authentication, and backup strategies

## 🛠️Technologies
SQL (MSSQL), Access Control, Secure Database Design ...

## 📝Project Overview
<img width="400" alt="image" src="https://github.com/user-attachments/assets/1ca7bd8c-9795-4f30-bdd7-c58e453b79f7" />

The system follows a clear separation of concerns, where **Assignment_DAMS.sql** represents the secured backend architecture, while each **login_*.sql** file simulates role-based frontend access aligned with RBAC and least-privilege principles.

| SQL File | Description |
|--------|--------|
| Assignment_DAMS | Core backend architecture script that defines the entire system structure, including database schema, tables, views, stored procedures, triggers, role-based permissions, auditing mechanisms, and security controls. |
| login_agent | Role-specific SQL script simulating the agent interface, allowing access only to authorized functions and data permitted for distributor agents. |
| login_analytics | Provides restricted analytical access for analytics roles to query reports, summaries, and business insights without modifying core data. |
| login_dba | Administrative SQL script granting database administrators elevated privileges for database maintenance, backup, restoration, and system monitoring. |
| login_it_admin | Enables IT administrators to manage system configurations, user access, and operational controls while enforcing least-privilege access. |
| login_marketing | Allows marketing personnel to access approved datasets and views relevant to campaigns while preventing exposure to sensitive data. |
| login_portaldev | Simulates developer access for portal maintenance and testing, limited to development-related operations without production-level privileges. |


Example: Agent with minimal access only

| Assigment_DAMS.sql (Backend) | login_agent.sql (Frontend) |
|--------|--------|
| <img width="400" alt="image" src="https://github.com/user-attachments/assets/9a7f6e45-282d-4c27-a27f-c49ee4834c06" /> | <img width="250" alt="image" src="https://github.com/user-attachments/assets/19513240-3d06-45e1-8452-5b8846ae8981" /> |


## 🔍 Main Focus (SQL Database Security Implementations)
### Data Protection
- **Hashing**

Hash password when a new agent is added.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/460e35df-da21-45d3-b595-c1c72d278880" />

- **Hashing + Salting**

Password hashing and salting when a new employee is added.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/460ba9ff-11c0-4b92-8413-50da71cc3b79" />

- **Data Obfuscation**

Sensitive informations are masked or hidden to unecessary role.
Ex: Agent emails, contact and address are restricted to Marketing.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/e7a71f59-0532-4ec1-bb40-fbc936af7a51" />

- **Encryption**

Master key acts as the top-level encryption key that protects other sensitive keys in the system.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/586f01af-96bd-4329-88bd-f3ffcfc2e66c" />

Below activates Transparent Data Encryption (TDE) for the database by 
creating a database encryption key using the strong AES 256 encryption algorithms and will be protected by the created certificate.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/7a2b107e-b3bb-43da-9d51-2bd1f45cec16" />

- **Backup & Restore**

Backup Master key and Certificate created.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/ba82116b-2c83-4512-839d-902d3df92239" />

- **Authentication (Session Handling & Session Expiry)**

When an Agent or Employee logs into the system, a session is created with a unique session id and tracked with timestamps including login time and last activity.
This ensure that only authenticated users can perform operations and users will be logged out automatically after 30 minutes.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/4378622a-7437-489d-89c2-56c5e81e1c2d" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/50dda9ef-d8c3-4e14-b8c5-4d49a97345c6" />

### Permission Management

- **Role-based permission (Grant, Deny etc)**

<img width="400" alt="image" src="https://github.com/user-attachments/assets/9a7f6e45-282d-4c27-a27f-c49ee4834c06" />

- **Row-level security (RLS) for Agent and Employee**

<img width="400" alt="image" src="https://github.com/user-attachments/assets/19d1f6ee-bfb4-4835-8459-712cc2dee454" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/a86942c8-1a5d-46d7-925b-e871dbe9b52e" />

### Auditing
Each techniques shows different type of auditing activity, such as login/logout activities, DML, DDL, DCL etc.

- **Server-level auditing**

<img width="400" alt="image" src="https://github.com/user-attachments/assets/63175586-9007-4a13-b007-6b40af2c9866" />

- **Database-level auditing**

<img width="250" alt="image" src="https://github.com/user-attachments/assets/e196db7a-ddfe-44b1-b79b-b0cde42d33d4" />

- **Audit log table & Triggers**

<img width="400" alt="image" src="https://github.com/user-attachments/assets/5b2b76b6-c3f3-4a18-b0fb-df8f31881ab3" />
<img width="400" alt="image" src="https://github.com/user-attachments/assets/c48f7dda-4a67-4f71-8ef9-cce3993bd92c" />


## ✅ Conclusion
Through this project, I gained a deeper understanding of how database security must be designed as part of the system architecture rather than treated as an afterthought. I learned that SQL-based systems often store highly sensitive information and therefore require strict access control, secure query handling, and well-defined privilege boundaries to prevent misuse and escalation attacks.

By implementing mechanisms such as role-based access control (RBAC), stored procedures, row-level security (RLS), views, data masking, and controlled session management, I developed practical insight into how secure database designs can effectively mitigate risks such as unauthorized access, horizontal and vertical privilege escalation, and data leakage. This project reinforced the importance of defensive database design, where users interact with controlled interfaces instead of raw tables, ensuring consistent enforcement of security checks.

Overall, the project strengthened my developer mindset toward secure system implementation, highlighting that strong database security is critical to preserving data confidentiality, integrity, and availability. It emphasized the role of secure SQL design in real-world systems and the need to align database controls with the principle of least privilege and secure-by-design development practices.

> Note: This project is based on a university assignment and has been adapted for **portfolio purposes**. All content is sanitized and does not include exploit payloads or sensitive information. 
