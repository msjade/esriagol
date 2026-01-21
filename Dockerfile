FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
ENV SERVICES_CONFIG=services.json
ENV CLIENTS_CONFIG=clients.json

# set these at runtime:
# ENV AGOL_USERNAME=...
# ENV AGOL_PASSWORD=...
# ENV PUBLIC_PROXY_BASE=https://proxy.yourdomain.com
# ENV ADMIN_KEY=...

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
