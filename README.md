# Vulnerability Management Tool

A Linux server vulnerability assessment tool designed with modular architecture for scalability and maintainability.
Each vulnerability check is managed independently, while common data collection logic and policy criteria are separated for maximum flexibility.

---

## 📁 Project Structure

```text
vuln-management-tool/
├─ app/
│  ├─ main/
│  ├─ checks/
│  ├─ collectors/
│  ├─ policies/
│  ├─ models/
│  ├─ output/
│  └─ common/
├─ config/
├─ docs/
├─ samples/
└─ reports/
```

---

## 📦 Folder Overview

### app/

Core module of the project containing the main logic for execution, evaluation, and result generation.

### app/main/

Controls the overall execution flow.
Determines which checks to run and manages the execution order.

### app/checks/

Contains individual vulnerability checks.
Each check is implemented as an independent module with its own validation logic and rules.

### app/collectors/

Handles reusable system data collection.
Includes logic for retrieving file contents, permissions, account information, PAM settings, service status, and package data.

### app/policies/

Manages security policies that vary by environment.
Supports default, hardened, and custom organizational policies.

### app/models/

Defines standardized data structures for storing and managing check results.

### app/output/

Handles result presentation.
Supports console output, JSON export, and report generation.

### app/common/

Contains shared utilities and common components such as constants, exception handling, and helper functions.

---

## ⚙️ Additional Directories

### config/

Stores global configuration such as execution options, environment settings, and logging configuration.

### docs/

Contains documentation for each vulnerability check, including descriptions, criteria, and remediation guidance.

### samples/

Provides example outputs for both secure and vulnerable cases.
Useful for testing and demonstration.

### reports/

Stores generated vulnerability assessment reports.
Acts as the output repository for scan results.

---

## 🎯 Design Principles

* Independent management of vulnerability checks
* Reusable and centralized data collection logic
* Policy-based evaluation adaptable to different environments
* Extensible output formats for various reporting needs

---

## 🚀 Key Benefits

* Easy to add new vulnerability checks
* Minimal impact when modifying existing logic
* High maintainability through clear separation of concerns
* Flexible adaptation to enterprise security requirements

---

## 📌 Overview

This project is structured to support scalable vulnerability assessment for Linux environments.
By separating checks, collectors, and policies, it ensures that updates and extensions can be made efficiently without affecting the entire system.
