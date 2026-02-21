FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install .
CMD ["python", "-m", "flask", "--app", "src.detector.app", "run", "--host=0.0.0.0", "--port=5000"]
