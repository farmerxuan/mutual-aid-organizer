FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .
RUN chmod +x docker-entrypoint.sh

ENV FLASK_APP=app
ENV PYTHONUNBUFFERED=1

EXPOSE 5000
VOLUME /app/data

CMD ["./docker-entrypoint.sh"]
