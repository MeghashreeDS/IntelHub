#  IntelHub – Threat Intelligent Collaborative Coding Platform

IntelHub is a secure, real-time collaborative coding platform that combines a modern development workflow with built-in cybersecurity controls. It allows multiple developers to code simultaneously in a shared environment while scanning for vulnerabilities before any code is committed.

This proof-of-concept project demonstrates how integrating threat intelligence into the software development lifecycle can reduce risks and enhance code quality from the ground up.

---

## 📁 Project Structure
IntelHub/
├── frontend/ # React.js frontend (UI, real-time collaboration)
├── backend/ # Flask backend (API, threat scans, auth)
├── exports/ # JSON-based threat intelligence database
├── README.md
└── .gitignore


---

##  Technologies Used

###  Frontend
- React.js (v18)
- WebSockets for real-time collaboration
- Monaco Editor for in-browser IDE

###  Backend
- Python Flask (v2.2)
- MongoDB for user/projects/repo data
- JWT for authentication
- Pygit2 for Git repository management

###  Threat Intelligence
- Custom threat scan engine
- Pre-commit vulnerability scanning
- Standalone analysis from JSON threat database (`exports/`)

---

##  Features

-  Real-time collaborative coding with WebSocket syncing  
-  Role-Based Access Control (RBAC) for secure project access  
-  Threat detection before code commits  
-  Git-based version control: branching, merging, commit history  
-  Standalone threat scan module for file/IP analysis  
-  Integrated browser IDE with syntax highlighting

---
##  Exports Folder

The `exports/` folder contains structured `.json` files that serve as the local threat intelligence database for IntelHub.

These files are used to:

-  Detect known vulnerabilities in code (e.g., hardcoded credentials, insecure patterns)
-  Identify malicious IP addresses and domain names
-  Check for unsafe libraries or dependencies
-  Flag suspicious or unsafe code before it is committed

The backend threat scanning engine uses this data for:

- Pre-commit vulnerability analysis
- Standalone file/IP scanning
- Threat intelligence reporting

##  Getting Started (Local Setup)

```bash
# 1. Clone the Repository
git clone https://github.com/MeghashreeDS/IntelHub.git
cd IntelHub

# 2. Install Backend Dependencies
cd backend
pip install -r requirements.txt

# 3. Install Frontend Dependencies
cd ../frontend
npm install

# 4. Run the App

# In one terminal, start the backend
cd ../backend
python app.py

# In another terminal, start the frontend
cd ../frontend
npm start









