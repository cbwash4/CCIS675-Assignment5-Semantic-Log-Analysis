# Semantic Cybersecurity Log Analysis Using MiniLM and ChromaDB

CCIS 675 Artificial Intelligence Assignment 5. This Python application searches
**exported** BOTS V3 events using `sentence-transformers/all-MiniLM-L6-v2` (384
features) and a persistent ChromaDB L2 collection named `incident_logs`.
Similarity retrieves investigation candidates; it does not establish malicious behavior.

## Setup

Use Python 3.11 or 3.12. Run commands from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
# CPU-only installation avoids unnecessarily downloading CUDA packages:
python -m pip install --index-url https://download.pytorch.org/whl/cpu torch==2.9.1
python -m pip install -r requirements.txt
python -m semantic_logs --help
```

For Colab GPU, retain Colab's compatible preinstalled PyTorch instead of the CPU
installation above. The model selects GPU when available; `--device cpu` or
`--device cuda` overrides selection. Initial model loading requires Internet access
to Hugging Face and approximately 100 MB of model weights; subsequent runs reuse
its cache. Set `HF_HOME` to a persistent location if desired. Model/API keys are
not needed for this public model. Package pins cover direct dependencies; upstream
model revisions and transitive dependencies are not fully locked.

## Obtain real BOTS V3 events

The original archive contains Splunk **pre-indexed** buckets (`.tsidx`,
`journal.gz`). These are not ordinary JSON gzip files. Do not decompress and treat
them as JSON, substitute BOTS V1, or label the synthetic fixture as BOTS V3.

Use an authorized Splunk installation compatible with the BOTS V3 release. Follow
the dataset's restoration instructions to load the buckets/app and confirm the
actual index name and sourcetypes. Search over **All time**, inspect sample events,
and record the event count, time bounds, sourcetypes, and export search. A typical
search, after confirming your index is `botsv3`, is:

```spl
index=botsv3 (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")
| fields _raw _time host sourcetype EventID EventCode UtcTime Image ParentImage CommandLine SourceIp DestinationIp DestinationPort TargetFilename
```

Use Splunk Search **Export**, choose JSON or CSV, and export all intended results
rather than a preview. For larger exports use an authorized Splunk REST search
export job with `output_mode=json`, then save its line-delimited `result` objects
as `.jsonl`. Do not store Splunk passwords or tokens in the project or notebook.
Verify the exported row count against the Splunk search and inspect representative
records before claiming coverage. Missing extracted fields may require Splunk
field extraction; the loader also reads JSON or Sysmon XML in `_raw` and multiline
`Field: value` text. It does not implement every Windows event encoding.

Supported files: JSON arrays, single objects, Splunk `results` arrays; JSONL objects
or Splunk `result` envelopes; CSV with headers. All input events must be JSON
objects. Nested source records are retained intact as serialized `raw_json` scalar
metadata. CSV values are preserved as strings. Do not upload confidential exports
to Git; `data/`, `results/`, and `forensic_db/` are ignored.

## Index and investigate

```bash
python -m semantic_logs index data/botsv3-export.jsonl --batch-size 64
python -m semantic_logs query 'Office applications launching command shells' --output results/office
python -m semantic_logs query 'Unexpected outbound network connections' \
  --event-ids 3 --after 2018-08-01T00:00:00Z --before 2018-09-01T00:00:00Z \
  --output results/network
python -m semantic_logs investigate --queries config/queries.json --output results/all_queries
```

The default DB is `./forensic_db`. Pass `--db PATH` on **every** command to use
another location. Default indexing selects EventIDs 1, 3, and 11. For broader
coverage use `--event-ids 1 3 11 12 13 14 19 20 21` or `--all-events`. This matters
for persistence and other techniques not represented by the default event types.
Missing/unrecognized EventID becomes -1 and is excluded by the default filter.
Missing/invalid timestamps remain indexed but cannot match time filters. Naive
timestamps are interpreted as UTC; filter bounds are inclusive.

Each narrative uses available Sysmon fields, without invented values. Original
records are included in every match. Chroma returns **squared Euclidean distance**;
outputs include `distance_l2_squared` and its square root `distance_l2`. Smaller
values mean nearer vectors. Embeddings are not normalized. No score threshold or
attack label is inferred. Queries return up to five events (fewer when fewer match).

Indexing prints processed, selected, filtered, empty, invalid-time, indexed-this-run,
and collection-total counts. Each query run prints query counts, result counts,
and original events, and writes `.json`, `.csv`, and `.summary.json` artifacts.
Repeated indexing of an unchanged file at the same absolute path upserts the same
IDs. Moving or reordering files creates new IDs; use a fresh DB for a clean
experiment. Partial indexing may remain if a later batch fails; unchanged-input
reruns resume via upserts. Do not mix synthetic and real data in the same DB.

## Validation and evidence

```bash
python -m pytest -m 'not integration' -q
# Requires public MiniLM weights; real model, synthetic input only:
python -m pytest -m integration -q
# Synthetic CLI demonstration, NOT a BOTS V3 experiment:
python -m semantic_logs index tests/fixtures/synthetic_events.json --db /tmp/synthetic_forensic_db
python -m semantic_logs investigate --db /tmp/synthetic_forensic_db --output /tmp/synthetic_results/all
```

The fixture explicitly sets `synthetic: true` and uses documentation-only IP ranges.
Fast tests use a deterministic encoder test double to verify plumbing. The separate
integration test verifies real MiniLM dimensions, insertion, retrieval, and export.
Passing either suite supplies no BOTS V3 detection accuracy or dataset coverage evidence.
See [methodology](docs/methodology.md) and [presentation outline](docs/presentation.md).

## Google Colab

Open `notebooks/semantic_log_analysis_colab.ipynb` in Colab and execute cells in
order. Exact terminal-style notebook commands are:

```python
!git clone https://github.com/cbwash4/CCIS675-Assignment5-Semantic-Log-Analysis.git /content/semantic-log-analysis
%cd /content/semantic-log-analysis
!python -m pip install -r requirements.txt
from google.colab import drive
drive.mount('/content/drive')
!python -m semantic_logs index '/content/drive/MyDrive/botsv3/exports/events.jsonl' --db '/content/drive/MyDrive/botsv3/forensic_db' --batch-size 64
!python -m semantic_logs investigate --db '/content/drive/MyDrive/botsv3/forensic_db' --output '/content/drive/MyDrive/botsv3/results/investigations'
```

Update the export path to your verified real events. These files must first be
committed and pushed before a fresh Colab clone can obtain them; alternatively
upload a zip of this working repository. The notebook includes export validation,
test execution, ingestion counts, and result inspection. Drive persists files;
processes and mounted connections must be recreated per session. For larger datasets,
a local `/content` DB followed by a stopped-client backup to Drive may be faster.

Limitations: pandas ingestion retains input files in memory; indexing is batched
but reading is not streaming. Use reasonably sized export shards. Narrative
construction covers common Sysmon fields rather than all event schemas. MiniLM
truncates long narratives at its token limit (typically 256 tokens); full raw
records are preserved but not entirely embedded. Data outside the export, omitted
event types, and missing fields cannot be recovered by semantic search. False
positives and missed relevant events are expected. No real BOTS V3 export has been
provided in this task; real-data measurements remain unrun.

Current workspace validation: **all 14 tests passed**, including actual pretrained
MiniLM inference. The CLI also indexed six selected synthetic events and executed
all ten queries with the real model. The earlier Hugging Face HTTP 403 blocker is
resolved. These checks demonstrate software functionality, not BOTS V3 performance.
See [validation record](docs/validation.md) for versions, scope, and evidence.
Actual Colab/GPU execution and real BOTS V3 experiments remain unverified.
Chroma's HNSW retrieval is approximate; top-five ordering does not guarantee
exhaustive exact neighbors.
