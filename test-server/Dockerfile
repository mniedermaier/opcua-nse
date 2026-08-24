FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY servers.py ./

EXPOSE 4840 4855 4885 4897 48010 62541

CMD ["python", "servers.py", "--mode", "insecure", "--port", "4840"]
