FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY hqnet /app/hqnet

RUN mkdir -p /data

WORKDIR /data

EXPOSE 6112
EXPOSE 9108

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import socket; s=socket.create_connection(('127.0.0.1', 6112), 3); s.close()"

CMD ["python", "-m", "hqnet", "--host", "0.0.0.0", "--port", "6112"]
