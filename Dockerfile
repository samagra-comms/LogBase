FROM python:3.9-alpine

WORKDIR /app

COPY log_base.py .
COPY DelayedKeyboardInterrupt.py .
COPY config_sample.json config.json
RUN mkdir logs

CMD ["python", "log_base.py"]
