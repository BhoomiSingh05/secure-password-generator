# 🔐 PassForge – Secure Password Generator

PassForge is a modern, security-focused web application built with Python Flask that enables users to generate cryptographically secure passwords, evaluate password strength, calculate entropy, and manage password history through an intuitive and responsive interface.

The application combines cybersecurity principles with modern web development practices to provide a reliable tool for creating strong passwords and understanding password security.

---

## 🚀 Key Features

### 🔑 Secure Password Generation

* Generate cryptographically secure passwords using Python's `secrets` module
* Custom password length selection
* Generate multiple passwords simultaneously
* Guaranteed inclusion of selected character types
* Support for:

  * Uppercase Letters (A-Z)
  * Lowercase Letters (a-z)
  * Numbers (0-9)
  * Special Symbols (!@#$%^&*)

### 📊 Password Strength Analysis

* Real-time password strength evaluation
* Categorization into:

  * Strong
  * Medium
  * Weak
* Visual strength indicators
* Strength score calculation (0–100)
* Character diversity assessment

### 🧮 Entropy Calculation

* Calculates password entropy in bits
* Estimates resistance against brute-force attacks
* Helps users understand password security mathematically

### 🔍 Custom Password Checker

* Analyze user-entered passwords
* Strength evaluation for existing passwords
* Entropy estimation
* Character variety analysis

### 📈 Statistics Dashboard

Automatically tracks:

* Total passwords generated
* Average password length
* Average entropy
* Strong password percentage
* Password strength distribution

### 📂 History Management

* Stores generated password history
* Displays recent password activity
* Clear history functionality
* Organized record management

### 📤 Export Functionality

* Export password history as CSV
* Structured data formatting
* Easy backup and reporting

### 🎨 Modern User Interface

* Responsive design
* Dark Mode / Light Mode support
* Show / Hide password feature
* One-click copy to clipboard
* Clean and user-friendly layout
* Glassmorphism-inspired design elements

---

## 🔒 Security Features

PassForge is designed with security as a primary objective.

### Cryptographically Secure Randomness

Passwords are generated using Python's built-in `secrets` module, which is specifically designed for security-sensitive applications.

### Guaranteed Character Diversity

The application ensures that every selected character category appears at least once in generated passwords.

### Secure Session Handling

User-generated results are stored securely during active sessions.

### Dynamic Secret Key Management

Secret keys are generated dynamically and can be configured using environment variables for deployment.

### Input Validation

Comprehensive validation prevents invalid inputs and improves application reliability.

### No Hardcoded Credentials

Sensitive information is never stored directly within the source code.

---

## 🛠️ Technology Stack

### Backend

* Python
* Flask

### Frontend

* HTML5
* CSS3
* JavaScript

### Security & Analysis

* Python Secrets Module
* Entropy Calculation
* Password Strength Algorithms
* Session Management

---

## 📂 Project Structure

```text
PassForge-Secure-Password-Generator/
│
├── app.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── static/
│   └── style.css
│
├── templates/
│   └── index.html
```

---

## 📊 Security Metrics Used

### Password Strength Score

Strength is calculated based on:

* Password length
* Character diversity
* Inclusion of uppercase letters
* Inclusion of lowercase letters
* Inclusion of numbers
* Inclusion of symbols

### Entropy Formula

Entropy is calculated using:

Entropy = Length × log₂(Character Pool Size)

Higher entropy values indicate stronger passwords and increased resistance to brute-force attacks.

---

## 🎯 Learning Outcomes

This project demonstrates practical implementation of:

* Secure password generation
* Cryptographic randomness
* Web application development using Flask
* Session management
* Data persistence
* Password security analysis
* Entropy calculation
* Frontend and backend integration
* User interface design
* Secure coding practices

---

## 🔮 Future Enhancements

* Password breach detection using external APIs
* Advanced password security analytics
* Password manager integration
* QR code password sharing
* Password expiration recommendations
* Multi-language support
* User authentication system
* Cloud database integration
* Security audit reports

---

## ⭐ Project Objective

The primary objective of PassForge is to provide a secure, educational, and user-friendly platform for password generation and security analysis while demonstrating modern cybersecurity concepts and full-stack web development practices.
