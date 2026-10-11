# Technical methodology for an IEEE course report

## Title and abstract plan
Semantic Cybersecurity Log Analysis Using MiniLM and ChromaDB. Describe the
problem of retrieving contextual evidence from exported cybersecurity logs, the
384-dimensional encoder, persistent L2 indexing, and ten investigation themes.
State the dataset actually used. Real BOTS V3 results and metrics are **pending**;
synthetic pipeline validation is not an attack-detection experiment.

## I. Introduction
Explain keyword-search limitations, event schema variability, and the need for
analyst-centered semantic retrieval. Objective: return five candidate events per
natural-language query with reproducible provenance, distances, and raw records.
Do not claim autonomous threat detection.

## II. Data and preprocessing
Document BOTS V3 source, permission, Splunk restoration version, index, sourcetypes,
export SPL, time bounds, and verified exported count. Native bucket archives are
not readable event CSV/JSON; obtain an actual Splunk export. Use pandas to read
JSON/JSONL/CSV into normalized tabular records. Preserve original records; map
EventCode and _time aliases and extract common Sysmon XML fields when needed.
Select EventIDs 1/3/11 by default, but explicitly report additions required by
registry, scheduled-task, and other investigations. Build labeled narratives
from fields actually present. Missing times cannot participate in time filters.

## III. Architecture and implementation
Exported events → pandas normalization → readable narratives → batched MiniLM
encoder → Chroma `incident_logs` → same encoder for query → L2 top-five retrieval
→ JSON/CSV and per-run summary. Components: preprocessing.py, embeddings.py,
store.py, and __main__.py. Use CPU or available CUDA, unnormalized 384-dimensional
vectors, a persistent database, scalar metadata, and serialized original records.
IDs hash absolute source path, row position, and canonical raw JSON. Repeated
unchanged input upserts; changed order/path requires a fresh DB for clean evaluation.
Chroma reports squared L2 distance; export both squared distance and Euclidean L2.
Collection metadata guards against mismatched model identity/configuration.

## IV. Experimental protocol
1. Use a fresh real-data DB, separate from synthetic fixtures.
2. Record hardware, Python/package versions, model revision, device, batch size,
   export hash/size, selection policy, and dataset provenance.
3. Verify counts against Splunk and inspect missing fields/time parsing.
4. Time ingestion, embedding/indexing, and each of the ten queries separately.
5. Save exact queries from config/queries.json and raw top-five outputs. Do not
   modify query wording after seeing results without recording a new experiment.
6. Have an analyst assess retrieved records in context. If labels are available,
   define relevance criteria and denominator before reporting precision@5 or
   recall. Without reviewed labels, report examples and retrieval counts only.

## V. Results to populate with real data
| Measurement | Value/status |
|---|---|
| Verified BOTS V3 events exported | PENDING: real export required |
| Processed / selected / filtered / empty | PENDING |
| Missing or invalid timestamps | PENDING |
| Indexed / collection total | PENDING |
| Runtime / hardware / model revision | PENDING |
| Per-query returned candidates and reviewed relevance | PENDING |
| Precision@5 or recall | NOT MEASURED; requires relevance labels |

Automated synthetic tests validate data handling, dimension checks, upserts,
persistence, filters, retrieval, and exports. Record actual run outcomes separately
from this table. The real-model integration test still uses synthetic input.

## VI. Discussion and limitations
Semantic resemblance is evidence for investigation, not a maliciousness judgment.
False positives, missing fields, truncated narratives, default event-type filtering,
small top-k, uneven dataset coverage, benign administrative activity, and model
bias may cause misleading or missed matches. Query themes such as credential
access may require context absent from selected events. No metrics should be
inferred from fabricated or synthetic events. Full records in outputs may expose
sensitive command lines: handle results under the dataset's access policy.

## VII. Conclusions and references
Conclude only what the executed checks establish. Separate verified software
functionality from pending dataset experiments. Cite primary sources using IEEE
numbered references: BOTS V3 dataset/release documentation
(https://github.com/splunk/botsv3), the model card
(https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2), Sentence-BERT paper
(https://arxiv.org/abs/1908.10084), Chroma documentation
(https://docs.trychroma.com/), and Splunk export documentation for the actual
installed Splunk version. Supply publication/version/access dates when finalizing.
