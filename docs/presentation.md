# Presentation outline

1. **Problem:** cybersecurity logs are large, heterogeneous, and hard to investigate with exact keywords.
2. **Objectives:** ingest verified BOTS V3 exports, embed narratives, retrieve five candidates, preserve provenance.
3. **Dataset:** explain native Splunk buckets versus event exports; state the actual export scope and counts when available.
4. **Architecture:** export → pandas → MiniLM (384 dimensions) → persistent Chroma L2 → queries → CSV/JSON.
5. **Implementation:** common Sysmon fields, event/time filters, batched CPU/GPU inference, original-record retention.
6. **Experiments:** list the ten assignment queries; separate synthetic tests from real BOTS V3 evaluation.
7. **Results:** insert measured counts, timings, and analyst-reviewed examples only after real-data execution. Currently PENDING.
8. **Limitations:** similarity is not maliciousness; missing coverage, false positives, truncation, and absent ground truth.
9. **Conclusions:** summarize verified engineering functionality and remaining real-data experiments.
10. **Demonstration:** run a labeled synthetic search or a verified real export; show distances and original events without inventing detections.
