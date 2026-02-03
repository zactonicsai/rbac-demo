FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir opensearch-py requests

# Copy setup script
COPY setup_opensearch.py .

# Run setup
CMD ["python", "setup_opensearch.py"]
