# How KubeSentinel Streamlit Works

1. The user uploads manifests, Terraform, Helm files, or audit logs from the Streamlit UI.
2. Uploaded files are saved under `uploads/` for traceability.
3. The scanner parses supported files and emits normalized findings with severity, category, rule ID, target, evidence, and remediation.
4. The app optionally retrieves local knowledge context from `vector_store/metadata.json` or Markdown files in `knowledge_base/`.
5. If Ollama summarization is enabled, the findings and retrieved context are sent to the configured local Ollama model.
6. CSV, HTML, PDF, and JSON logs are generated under `reports/` and `logs/`, and are also available as in-browser downloads.

The RAG ingestion flow is:

```text
knowledge_base/**/*.md
  -> ingest_docs.py
  -> vector_store/metadata.json
  -> optional vector_store/faiss.index
  -> Streamlit AI summary context
```
