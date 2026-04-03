# 🛡️ Sentinel AI Remediator
**Automated Security Auditing & AI-Powered Patch Generation**

Sentinel AI Remediator is a sophisticated security tool that leverages **Bandit** for static analysis and **OpenAI GPT-4o mini** to provide intelligent, context-aware remediation for Python code.

---

## 📊 System Architecture
![System Architecture](./sentinel_guard_architecture.svg)

---

## 🚀 Key Features
* **Automated Scanning:** Detects critical vulnerabilities like Shell Injections (CWE-78) and Weak Hashes (CWE-327).
* **AI Remediation:** Generates secure code replacements and provides detailed explanations for every vulnerability.
* **Secure Dashboard:** Integrated with **Auth0** for professional-grade user authentication.

---

## 🛠️ How to Run Locally
1. **Clone the Repo:** `git clone https://github.com/yashrajkshatriya74-star/Sentinel-AI-Remediator.git`
2. **Install Dependencies:** `pip install -r requirements.txt`
3. **Environment Setup:** Rename `.env.example` to `.env` and add your `OPENAI_API_KEY` and `AUTH0` credentials.
4. **Launch:** `python main.py`
