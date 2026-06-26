FROM python:3.12-slim

LABEL org.opencontainers.image.title="AI-Driven Security Analyzer"
LABEL org.opencontainers.image.description="AI-powered SAST/DAST result analyzer for Kubernetes"
LABEL org.opencontainers.image.source="https://github.com/madhucnghubphilips/AI-Driven-K8s"

# Create non-root user
RUN groupadd -r analyzer && useradd -r -g analyzer -s /sbin/nologin analyzer

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer.py .

RUN chown -R analyzer:analyzer /app
USER analyzer

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/health')"

CMD ["python", "analyzer.py"]
