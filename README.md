# AWS Capstone Project – BloodBridge

## 🩸 BloodBridge: Cloud-Based Blood Donation & Request Platform

BloodBridge is a full-stack web application developed as an **AWS Capstone Project**. The platform connects **donors, recipients, blood banks, and administrators** to streamline blood donation, blood requests, and inventory management using cloud services.

---

## 🚀 Features

* 👤 **User Roles**: Donor, Recipient, Blood Bank, Admin
* 🩸 **Blood Requests & Donations**
* 📅 **Schedule Blood Donations**
* 📊 **Dashboards for Each Role**
* 🔐 **Role-based Access Control (IAM ready)**
* ☁️ **Cloud-ready architecture (AWS-oriented)**

---

## 🛠️ Tech Stack

### Backend

* Python
* Flask
* AWS (IAM, EC2 – integration ready)

### Frontend

* HTML5
* CSS3
* JavaScript

### Database / Storage

* File / JSON based storage (extendable to DynamoDB)

---

## 📁 Project Structure

```
AWS_Capstone-BloodBridge/
│
└── blood bridge - AWS/
    │
    ├── backend/
    │   ├── data/                       # Application data storage
    │   ├── IAM_POLICY_TEMPLATE.json     # AWS IAM policy template
    │   ├── app.py                      # Flask application entry point
    │   ├── choose_role_route_stub.txt   # Route reference
    │   ├── data_store.py               # Data handling logic
    │   └── requirements.txt            # Python dependencies
    │
    └── frontend/
        ├── js/
        │   └── main.js                 # Frontend JavaScript
        │
        ├── static/
        │   └── css/
        │       └── style.css           # Application styles
        │
        └── templates/
            ├── base.html
            ├── index.html
            ├── login.html
            ├── signup.html
            ├── about.html
            ├── contact.html
            ├── choose_role.html
            ├── dashboard.html
            ├── admin_dashboard.html
            ├── donor_dashboard.html
            ├── recipient_dashboard.html
            ├── bloodbank_dashboard.html
            ├── request_blood.html
            ├── schedule_donation.html
            └── view_requests_for_donors.html
```

---

## ▶️ How to Run the Project Locally

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/Adsharma18/AWS_Capstone-BloodBridge.git
cd AWS_Capstone-BloodBridge
```

### 2️⃣ Setup Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

### 3️⃣ Install Dependencies

```bash
pip install -r backend/requirements.txt
```

### 4️⃣ Run Flask Server

```bash
cd backend
python app.py
```

### 5️⃣ Open in Browser

```
http://127.0.0.1:5000/
```

---

## ☁️ AWS Deployment (Future Scope)

* Deploy backend on **EC2**
* Use **IAM roles** for secure access
* Replace local storage with **DynamoDB**
* Serve static files via **S3 + CloudFront**

---

## 🎓 Academic Context

* **Project Type**: AWS Capstone Project
* **Domain**: Cloud Computing & Web Development
* **Use Case**: Healthcare / Blood Donation System

---

## 👩‍💻 Author

**Aditi Sharma**
AWS Capstone Project

---

## 📜 License

This project is created for educational purposes.
