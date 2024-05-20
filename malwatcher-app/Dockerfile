FROM python:3.12-slim

WORKDIR /malwatcher-app
COPY . .

RUN apt update && apt install -y nodejs npm

RUN pip install --no-cache-dir -r requirements.txt

RUN npm install
RUN npx tailwindcss init
RUN npx tailwindcss -i src/tailwind.css -o app/static/css/styles.css
RUN npm run build

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "main:app"]