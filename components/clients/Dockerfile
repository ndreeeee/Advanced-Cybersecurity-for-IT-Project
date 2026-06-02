FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl iputils-ping && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir fastapi uvicorn requests jinja2
WORKDIR /app
COPY templates/ ./templates/
COPY static/ ./static/
COPY simulator.py .
CMD ["uvicorn", "simulator:app", "--host", "0.0.0.0", "--port", "8000"]
