# docker build -t im-malwatcher-worker .
# docker run -d -v ./logs:/worker/logs -p 4000:8080 --name malwatcher-worker im-malwatcher-worker

FROM python:3.12-slim

WORKDIR /worker
COPY ./ /worker/
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "worker.py"]
