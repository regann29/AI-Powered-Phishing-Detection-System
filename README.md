# 🛡️ AI-Powered Phishing Detection System

An intelligent security tool that helps people identify fake websites and suspicious emails before they become victims of online scams.

The system uses Machine Learning to examine website links and email messages, identify suspicious signs, and calculate a risk score from **0 to 100**. It also explains why something might be dangerous in simple language.

**Our goal:** Make online communication safer by helping people recognize phishing attacks before they cause harm.

---

## 📌 1. What Is This Project?

Phishing is a type of online scam where attackers create fake websites or send misleading emails to trick people into sharing sensitive information, such as passwords, banking details, or personal data.

For example:
- You receive an email claiming that your bank account will be blocked unless you verify your information.
- Someone sends you a fake login link that looks like a real website.
- A message asks you to click a suspicious link to claim a prize.

Our project helps detect these threats automatically.

Instead of asking users to identify every suspicious detail themselves, our system uses Artificial Intelligence and Machine Learning to examine the information and provide an easy-to-understand security report.

## ⚙️ 2. What Does Our Project Do?

The system has two main detection features:

### A. Suspicious Website Detection

Users can enter a website link, and the system checks whether it contains suspicious characteristics.

It looks for signs such as:
- Unusually long or complicated website addresses.
- Fake website names that look similar to trusted brands.
- Suspicious symbols or unusual website structures.
- Links that use misleading domain names.
- Other patterns commonly found in phishing websites.

**Result:** The system provides a risk score and explains the suspicious characteristics it found.

### B. Suspicious Email Detection

Users can submit an email's sender information, subject, and message.

The system examines the email for warning signs such as:
- Messages creating urgency or fear.
- Requests for passwords or personal information.
- Suspicious links hidden behind normal-looking text.
- Mismatched sender and reply addresses.
- Language commonly used in phishing messages.

**Result:** The system identifies potentially dangerous emails, highlights suspicious links and words, and explains why the email may be unsafe.

---

## 🧠 3. How Does It Work?

Our project follows a simple process:

1. **User Input:** The user submits a website link or email.
2. **Information Analysis:** The system examines the content and searches for suspicious patterns.
3. **Machine Learning:** A trained model compares the information with patterns learned from previously labelled examples.
4. **Risk Calculation:** The system generates a risk score between 0 and 100.
5. **Security Report:** The user receives the result along with understandable warning signs.

### Understanding the Risk Score

| Score | Risk Level | Meaning |
|---|---|---|
| 0–34 | Low | Fewer suspicious signs were detected. |
| 35–69 | Medium | Some suspicious characteristics were found. |
| 70–100 | High | Strong phishing-related warning signs were detected. |

**Important:** A low score does not guarantee that a website or email is safe. The system helps identify potential threats, but it cannot detect every phishing attack.

---

## 🛠️ 4. Technologies We Used

We selected these technologies to build a complete web-based security application.

| Technology | What We Use It For |
|---|---|
| Python | Building the main detection system. |
| Scikit-learn | Training Machine Learning models to identify suspicious patterns. |
| Flask | Connecting the detection system to the website. |
| React.js | Building the user interface that people interact with. |
| PostgreSQL | Managing user accounts and scan history. |

### Machine Learning Models

We use two different models:

- **Random Forest:** Helps identify suspicious website links by examining their structure and characteristics.
- **Logistic Regression:** Helps classify emails by examining their content and suspicious patterns.

Using different models allows us to analyze website links and emails according to their different characteristics.

---

## 🚀 5. How to Run the Project

Follow these steps to run the project on your computer.

### Requirements

Before starting, install:
- Python
- Node.js and npm
- Git
- PostgreSQL (or use the provided Docker setup)

### Step 1: Download the Project

Clone the GitHub repository and open the project folder.

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd YOUR_PROJECT_FOLDER
```

### Step 2: Start the Database

If Docker is installed, run:

```bash
docker compose up -d db
```

### Step 3: Set Up the Backend

Open the backend folder:

```bash
cd backend
```

Create a Python virtual environment:

```bash
python -m venv .venv
```

Activate it:

**Windows:**
```bash
.venv\Scripts\activate
```

**Mac/Linux:**
```bash
source .venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Create your environment configuration:

```bash
cp .env.example .env
```

On Windows Command Prompt, use:

```cmd
copy .env.example .env
```

Set a secure `JWT_SECRET_KEY` in your `.env` file.

### Step 4: Prepare the Machine Learning Models

Run the following command:

```bash
python -m app.ml.train --demo
```

This creates demonstration models using generated sample data.

**Note:** Demonstration models are only for testing the application. Real-world detection requires properly labelled phishing and legitimate datasets.

### Step 5: Start the Backend Server

```bash
python run.py
```

The backend will run at:

`http://127.0.0.1:5000`

### Step 6: Start the Frontend

Open another terminal and navigate to the frontend folder:

```bash
cd frontend
```

Install the required packages:

```bash
npm install
```

Start the website:

```bash
npm run dev
```

Open the local website address displayed in your terminal, usually:

`http://localhost:5173`

### Step 7: Run Tests

To check whether the backend is working correctly:

```bash
cd backend
pytest
```

---

## 🔐 6. Security and Privacy Features

We designed the project with user security and privacy in mind.

Some important security measures include:

- **Secure Login:** Passwords are stored in a protected, hashed format rather than plain text.
- **User Protection:** Each user can access only their own scan history.
- **Data Privacy:** Full email messages and complete website links are not stored in the database.
- **Scan History Management:** Users can view and delete their previous scan results.
- **Request Protection:** The system limits repeated requests to reduce misuse.
- **Input Validation:** The application checks submitted information before processing it.
- **Safe URL Analysis:** The server analyzes website addresses as text instead of opening them. This prevents the scanning process from directly visiting potentially dangerous websites.

---

## 🌟 7. Main Advantages of Our Project

Here are some of the major benefits:

**1. Early Threat Detection**

Helps users recognize potentially dangerous websites and emails before interacting with them.

**2. Easy to Understand**

Provides simple explanations instead of showing users only technical security information.

**3. Two-in-One Protection**

Checks both suspicious website links and potentially harmful emails in one application.

**4. AI-Powered Analysis**

Uses Machine Learning to recognize suspicious patterns and classify potential phishing attempts.

**5. Better Security Awareness**

Helps users understand common phishing techniques and become more careful online.

**6. Privacy-Focused Design**

Avoids storing complete email messages and website links in the scan history.

**7. Accessible Through a Website**

Users can access the detection system through a web interface without needing to understand how Machine Learning works.

---

## ⚠️ 8. Current Limitations

Although our system can identify many suspicious patterns, it is not perfect.

- Some advanced phishing attacks may not be detected.
- A suspicious website can sometimes receive a low risk score.
- The system does not currently check website ownership history or domain reputation.
- Detection quality depends heavily on the quality and variety of the training data.
- Demonstration models are not suitable for real-world security decisions.

**Our approach:** Treat the results as security guidance, not a guarantee that something is safe or dangerous.

---

## 🔮 9. Future Improvements

We aim to improve the project by adding features such as:

- Real-time website reputation checking.
- More advanced Machine Learning models.
- Improved detection of newly created phishing techniques.
- Browser extension for checking links while browsing.
- More detailed security reports.
- Integration with trusted threat-intelligence sources.
- Improved email analysis and detection accuracy.

---

## 🎯 10. Our Mission

Our mission is to make online security easier and more accessible to everyone.

We believe people should not need advanced technical knowledge to recognize online threats. By combining Artificial Intelligence, Machine Learning, and a simple user interface, we aim to help individuals make safer decisions online.

**Built with Python, Machine Learning, Flask, React.js, and PostgreSQL.**

