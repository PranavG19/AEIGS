FROM python:3.12-slim
WORKDIR /app
ENV POETRY_VIRTUALENVS_CREATE=false
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry install --only main --no-root --no-interaction
COPY . .
EXPOSE 5001
HEALTHCHECK --interval=5s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')" || exit 1
CMD ["python", "app.py"]
