# KubeSentinel Streamlit Application

This is a Streamlit edition of KubeSentinel with screens for Kubernetes SAST, Kubernetes DAST, Terraform, Helm Charts, Audit Logs, Knowledge Base ingestion, and report downloads.

## Folder layout

```text
app/
  rules/
knowledge_base/
logs/
reports/
  csv/
  html/
  pdf/
uploads/
vector_store/
streamlit_app.py
ingest_docs.py
requirements.txt
requirements-rag.txt
setup.bat
setup.sh
package_app.py
```

## Run on Windows

```bat
setup.bat
```

Or run the steps manually:

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Run on Linux or macOS

```bash
chmod +x setup.sh
./setup.sh
```

## Using the knowledge base

Copy Markdown security knowledge into `knowledge_base/`, then run:

```bash
python ingest_docs.py
```

The default ingestion writes `vector_store/metadata.json`, which the Streamlit app can use for keyword-based context. To also create `vector_store/faiss.index`, install the optional RAG packages:

```bash
pip install -r requirements-rag.txt
python ingest_docs.py
```

## Migrating from the Flask KubeSentinel ZIP

Copy these folders from the original application into this Streamlit folder when you want to reuse existing material:

- `knowledge_base/` for Markdown security data
- `vector_store/` for existing RAG artifacts
- `uploads/`, `logs/`, and `reports/` if you want to retain previous scan history
- `app/rules/` if you want to keep rule documentation beside this implementation

The Streamlit app includes its own scanner logic, so it can run without the original Flask routes and templates.

## Features

- K8s SAST: upload Kubernetes YAML or JSON manifests.
- K8s DAST: upload cluster snapshots or run read-only `kubectl get` snapshots from the current kubeconfig context.
- Terraform: scan EKS, IAM, and Kubernetes secret patterns.
- Helm Charts: scan Chart.yaml, values files, and template YAML.
- Audit Logs: scan Kubernetes JSONL or text audit logs.
- LLM details: optional Ollama summary through `http://localhost:11434`.
- Reports: CSV, HTML, PDF downloads and saved scan logs.

## Create a ZIP package

From inside this folder, run:

```bat
package_app.bat
```

or:

```bash
python package_app.py
```

This creates `KubeSentinel_Streamlit_App.zip` one level above the app folder.

## Notes

The live DAST mode only runs read-only `kubectl get` commands. It does not retrieve Secret values. The static checks are intentionally conservative and should be treated as a security triage layer, not a replacement for policy-as-code gates such as Kyverno, OPA Gatekeeper, or admission control.
