# Validation record — October 11, 2026

Following publication of the cloud environment, actual pretrained model download
and CPU inference succeeded. The earlier Hugging Face proxy HTTP 403 is resolved.

## Software and model

- Python 3.12.14; PyTorch 2.9.1+cpu.
- sentence-transformers 5.1.2; transformers 4.57.6.
- ChromaDB 1.3.5; pandas 2.2.3; NumPy 2.2.6.
- Actual public pretrained `sentence-transformers/all-MiniLM-L6-v2` downloaded
  from Hugging Face, cache revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`.
- Embeddings verified finite and 384-dimensional. Device: CPU.

## Executed checks

| Check | Actual outcome |
|---|---|
| Install/verify `requirements.txt` | All declared versions satisfied |
| `python -m pip check` | No broken requirements |
| `python -m pytest -q` | **14 passed, 0 failed, 0 skipped** in 17.62 seconds |
| Actual MiniLM integration test | Passed: embeddings, Chroma insertion, retrieval, export |
| Real-model CLI `index` | Passed on explicitly synthetic fixture: 7 processed, 6 indexed, 1 filtered |
| Real-model CLI `query` | Passed: 5 candidates with raw records and finite distances |
| Real-model CLI `investigate` | Passed: all 10 exact configured queries, 50 match rows, CSV and JSON exports |
| Notebook JSON structure and Python-cell syntax | Passed; actual Colab execution not performed |
| `git diff --check` | Passed |
| Actual BOTS V3 processing / investigation | **Not run: real event export not supplied** |

The full suite includes 13 fast tests with a deterministic test encoder and one
integration test using actual pretrained MiniLM weights. The additional CLI run
uses the real MiniLM encoder throughout, but its input remains entirely synthetic.
None of these outcomes measures BOTS V3 performance, coverage, attack detection
accuracy, or relevance. No real BOTS V3 events have been processed.

One nonblocking dependency warning was emitted: Hugging Face's `hf_xet.download_files()`
is deprecated. There were no remaining test or CLI errors.

## Reproduce

From the repository root with the virtual environment activated:

```bash
export HF_HOME=/workspace/.cache/huggingface
python -m pytest -q
python -m semantic_logs index tests/fixtures/synthetic_events.json --db /tmp/minilm-cli-validation/forensic_db --batch-size 2
python -m semantic_logs query 'Office applications launching command shells' --db /tmp/minilm-cli-validation/forensic_db --output /tmp/minilm-cli-validation/results/office
python -m semantic_logs investigate --db /tmp/minilm-cli-validation/forensic_db --output /tmp/minilm-cli-validation/results/investigations
```

The current CLI artifacts are outside the checkout in `/tmp/minilm-cli-validation`;
full test output is in `/tmp/semantic-revalidation.log`. These are synthetic
engineering validation artifacts, not assignment experimental results.

## Colab and Git status

The CPU pipeline is validated and ready to try using the supplied Colab notebook.
Colab execution, Drive persistence behavior, GPU inference, large-export memory
behavior, and real-event relevance remain unverified. Use Colab's compatible
preinstalled PyTorch rather than replacing it with CPU-only PyTorch if using GPU.
Provide a verified Splunk BOTS V3 JSON/JSONL/CSV export before claiming dataset
experiments. The native `journal.gz`/`.tsidx` archive is not a supported event export.

At validation, GitHub `main` still pointed to initial commit
`08d34c52640eedf20647ab34d710090db78f2a28` and contained only README.md and .gitignore.
The application changes are prepared locally for a commit; they have not been
committed or pushed. Publishing the cloud environment does not publish code to
GitHub. Upload the current repository to Colab, or commit and push the changes
before relying on the notebook's GitHub clone cell.
