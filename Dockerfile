FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY probe.py /app/probe.py

# Pennsieve runs app containers as uid 1000 whatever USER says; the probe needs
# nothing beyond the standard library.
ENTRYPOINT ["python", "/app/probe.py"]
