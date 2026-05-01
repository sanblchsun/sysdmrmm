# rmm_cpp/Dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.125.0 uvicorn[standard]==0.38.0 pydantic==2.12.5

COPY ./server /app/server

EXPOSE 8001

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8001", "--proxy-headers", "--forwarded-allow-ips=*"]
