FROM python:3.11-slim
RUN pip install --no-cache-dir fastapi uvicorn requests jinja2
WORKDIR /app
COPY templates/ ./templates/
COPY static/ ./static/
COPY simulator.py .
CMD ["uvicorn", "simulator:app", "--host", "0.0.0.0", "--port", "8000"]
