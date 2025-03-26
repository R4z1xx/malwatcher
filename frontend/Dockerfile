FROM node:23-slim AS frontend-builder
WORKDIR /build

COPY package*.json .
COPY tailwind.config.js .
COPY postcss.config.js .
COPY src/tailwind.css ./src/
COPY app/templates/ ./app/templates/

RUN npm install && \
    npx tailwindcss -i ./src/tailwind.css -o ./app/static/css/styles.css

# ---

FROM python:3.13-slim
WORKDIR /malwatcher-app

COPY --from=frontend-builder /build/app/static/css/styles.css ./app/static/css/
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m -u 1001 appuser && \
    chown -R appuser:appuser /malwatcher-app

USER appuser

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "main:app"]