FROM python:3.12-alpine

WORKDIR /app
COPY app.py .
COPY report.py .

ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/app.py"]
