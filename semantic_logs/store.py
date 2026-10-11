"""Persistent L2 vector retrieval with scalar metadata and intact raw JSON."""
import json
import math
from pathlib import Path

import chromadb
import pandas as pd
from chromadb.config import Settings

from .embeddings import DIMENSION, validate_vectors


class LogStore:
    def __init__(self, path='./forensic_db', model_name=None, create=False):
        if not model_name:
            raise ValueError('An explicit embedding model identity is required')
        self.client = chromadb.PersistentClient(path=str(path), settings=Settings(anonymized_telemetry=False))
        if create:
            self.collection = self.client.get_or_create_collection(
                name='incident_logs', embedding_function=None,
                metadata={'hnsw:space': 'l2', 'embedding_model': model_name,
                          'embedding_dimension': DIMENSION, 'normalized': False})
        else:
            self.collection = self.client.get_collection('incident_logs', embedding_function=None)
        metadata = self.collection.metadata or {}
        if (metadata.get('embedding_model') != model_name or
                metadata.get('hnsw:space') != 'l2' or
                metadata.get('embedding_dimension') != DIMENSION or
                metadata.get('normalized') is not False):
            raise ValueError('Collection model/distance configuration does not match; use a separate DB')

    def index(self, frame, encoder, batch_size=64):
        if batch_size < 1:
            raise ValueError('batch_size must be positive')
        written = 0
        limit = min(batch_size, self.client.get_max_batch_size())
        for start in range(0, len(frame), limit):
            rows = frame.iloc[start:start + limit].to_dict('records')
            documents = [row['text_payload'] for row in rows]
            vectors = validate_vectors(encoder.encode(documents, batch_size=limit), len(rows))
            metadata = []
            for row in rows:
                entry = {key: row[key] for key in ('EventID', 'UtcTime', 'source_file', 'raw_json')}
                for key in ('Image', 'ParentImage', 'CommandLine', 'SourceIp', 'DestinationIp',
                            'DestinationPort', 'TargetFilename'):
                    if row[key]:
                        entry[key] = row[key]
                if row['timestamp'] is not None and not math.isnan(row['timestamp']):
                    entry['timestamp'] = row['timestamp']
                metadata.append(entry)
            self.collection.upsert(ids=[row['id'] for row in rows], documents=documents,
                                   embeddings=vectors.tolist(), metadatas=metadata)
            written += len(rows)
        return {'indexed_this_run': written, 'collection_total': self.collection.count()}

    def query(self, text, encoder, event_ids=None, after=None, before=None, limit=5):
        if not text.strip() or limit < 1:
            raise ValueError('Query must be nonempty and limit must be positive')
        clauses = []
        if event_ids:
            clauses.append({'EventID': {'$in': [int(value) for value in event_ids]}})
        bounds = []
        for value, operator in ((after, '$gte'), (before, '$lte')):
            if value:
                stamp = pd.to_datetime(value, utc=True, errors='raise').timestamp()
                clauses.append({'timestamp': {operator: stamp}})
                bounds.append(stamp)
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise ValueError('--after must not be later than --before')
        if not self.collection.count():
            return []
        where = clauses[0] if len(clauses) == 1 else {'$and': clauses} if clauses else None
        vector = validate_vectors(encoder.encode([text]), 1)
        result = self.collection.query(query_embeddings=vector.tolist(),
                                       n_results=min(limit, self.collection.count()), where=where,
                                       include=['documents', 'metadatas', 'distances'])
        return [{'rank': rank, 'id': identity, 'distance_l2_squared': float(distance),
                 'distance_l2': float(math.sqrt(max(0.0, distance))),
                 'text_payload': document, 'metadata': {k: v for k, v in meta.items() if k != 'raw_json'},
                 'original_event': json.loads(meta['raw_json'])}
                for rank, (identity, distance, document, meta) in enumerate(zip(
                    result['ids'][0], result['distances'][0], result['documents'][0],
                    result['metadatas'][0]), 1)]


def export_results(results, prefix):
    """Write JSON and CSV, including nested original records as JSON in CSV."""
    path = Path(prefix)
    path.parent.mkdir(parents=True, exist_ok=True)
    json_path, csv_path = Path(str(path) + '.json'), Path(str(path) + '.csv')
    json_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    columns = ('query_id', 'query', 'rank', 'id', 'distance_l2', 'distance_l2_squared',
               'text_payload', 'metadata', 'original_event')
    flat = [{**row, 'metadata': json.dumps(row.get('metadata', {}), ensure_ascii=False),
             'original_event': json.dumps(row.get('original_event', {}), ensure_ascii=False)} for row in results]
    pd.DataFrame(flat, columns=columns).to_csv(csv_path, index=False)
    return str(json_path), str(csv_path)
