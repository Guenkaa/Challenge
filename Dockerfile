FROM python:3.9-slim

WORKDIR /app

COPY capture_packets.py .

RUN apt-get update && apt-get install -y iproute2

RUN pip install scapy

CMD ["python", "capture_packets.py"]