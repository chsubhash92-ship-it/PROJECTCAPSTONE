# Use high-performance Python base image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Step 1: Install system dependencies
COPY requirements.txt .
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Step 2: Pre-install heavy ML dependencies (to improve caching and avoid aggregate timeout)
RUN pip install --no-cache-dir \
    numpy \
    pandas \
    scikit-learn \
    tensorflow-cpu \
    xgboost \
    shap

# Step 3: Install remaining requirements
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir gunicorn

# Copy all application files
COPY . .

# Start application
# Railway/Cloud services will override the PORT env var
CMD gunicorn --bind 0.0.0.0:$PORT --timeout 300 app:app
