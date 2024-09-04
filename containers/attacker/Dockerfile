FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask>=3.0
COPY containers/attacker/controller.py .
EXPOSE 9000
CMD ["python", "controller.py"]
