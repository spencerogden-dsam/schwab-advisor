FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir poetry-core
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

CMD ["uvicorn", "schwab_advisor.server:app", "--host", "0.0.0.0", "--port", "8080"]
