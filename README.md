

### **1. Clone the Repository**

```bash
git clone https://github.com/Vansh-22f300/parking_app.git
cd parking_app
```

### **2. Backend Setup**

```bash
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Start Redis server (in separate terminal)
redis-server

# Start Celery worker (in separate terminal)
python -m celery -A celery_app.celery worker --loglevel=info

# Start Celery beat scheduler (in separate terminal)
python -m celery -A celery_app.celery beat --loglevel=info

# Start Flask application which will create database too
python app.py
```

### **3. Frontend Setup**

```bash
cd frontend

# Install Node.js dependencies
npm install

# Start development server
npm run dev
```

