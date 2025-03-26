FROM python:3.13-slim

WORKDIR /worker

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1001 worker && \
    chown -R worker:worker /worker
USER worker

CMD ["python", "worker.py"]