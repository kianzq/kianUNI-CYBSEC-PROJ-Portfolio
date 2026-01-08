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









## ✅ Conclusion → Summary & learnings



> Note: This project is based on a university assignment and has been adapted for portfolio purposes. All content is sanitized and does not include exploit payloads or sensitive information.
