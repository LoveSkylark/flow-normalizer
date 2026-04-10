FROM python:3.11-slim
WORKDIR /app
COPY proxy.py .
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import socket,os; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',int(os.environ.get('SFLOW_PORT',6343)))); s.close()"
CMD ["python", "-u", "proxy.py"]
