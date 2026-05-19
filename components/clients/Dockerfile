FROM python:3.11-slim
RUN pip install --no-cache-dir pymongo
WORKDIR /app
COPY simulator.py .
CMD ["python", "simulator.py"]
