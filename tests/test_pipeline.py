import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from semantic_logs.embeddings import MiniLMEncoder, MODEL_NAME, validate_vectors
from semantic_logs.preprocessing import load_events
from semantic_logs.store import LogStore, export_results

FIXTURE = Path(__file__).parent / 'fixtures/synthetic_events.json'


class DeterministicTestEncoder:
    """Test double only: these vectors are not MiniLM experimental evidence."""
    model_name = 'synthetic-test-double-v1'

    def encode(self, texts, batch_size=64):
        vectors = np.zeros((len(texts), 384), dtype=np.float32)
        for index, text in enumerate(texts):
            vectors[index, 0] = text.lower().count('powershell')
            vectors[index, 1] = text.lower().count('cmd.exe')
            vectors[index, 2] = text.lower().count('notepad')
        return vectors


def test_preprocessing_and_raw_preservation():
    frame, stats = load_events([FIXTURE])
    assert stats == {'processed': 7, 'selected': 6, 'filtered': 1, 'empty': 0, 'invalid_or_missing_time': 0}
    assert set(frame.EventID) == {1, 3, 11}
    assert 'ParentImage:' in frame.iloc[0].text_payload
    assert json.loads(frame.iloc[0].raw_json)['nested']['tags'] == ['test', 'office']
    assert len(set(frame.id)) == 6
    extra, _ = load_events([FIXTURE], [1, 3, 11, 13])
    assert len(extra) == 7


@pytest.mark.parametrize('suffix', ['json', 'jsonl', 'csv'])
def test_splunk_export_formats(tmp_path, suffix):
    event = {'EventCode': '3', '_time': '2018-08-20T10:01:00Z', 'Image': 'powershell.exe', 'DestinationPort': '443'}
    path = tmp_path / f'export.{suffix}'
    if suffix == 'csv':
        pd.DataFrame([event]).to_csv(path, index=False)
    elif suffix == 'jsonl':
        path.write_text(json.dumps({'result': event}) + '\n')
    else:
        path.write_text(json.dumps({'results': [event]}))
    frame, stats = load_events([path])
    assert stats['processed'] == 1
    assert frame.iloc[0].EventID == 3
    assert frame.iloc[0].DestinationPort == '443'


def test_xml_and_missing_times(tmp_path):
    path = tmp_path / 'export.json'
    path.write_text(json.dumps([{'_raw': '<Event><System><EventID>1</EventID></System><EventData><Data Name="Image">cmd.exe</Data></EventData></Event>'}]))
    frame, stats = load_events([path])
    assert frame.iloc[0].Image == 'cmd.exe'
    assert stats['invalid_or_missing_time'] == 1
    encoder = DeterministicTestEncoder()
    store = LogStore(tmp_path / 'db', encoder.model_name, create=True)
    store.index(frame, encoder)
    assert store.query('cmd.exe', encoder, after='2018-01-01') == []


def test_reject_native_splunk_archive(tmp_path):
    path = tmp_path / 'journal.gz'
    path.write_bytes(b'not event JSON')
    with pytest.raises(ValueError, match='not event exports'):
        load_events([path])


def test_dimensions_and_finite_values():
    assert validate_vectors(np.zeros((2, 384)), 2).shape == (2, 384)
    with pytest.raises(ValueError):
        validate_vectors(np.zeros((2, 383)), 2)
    with pytest.raises(ValueError):
        validate_vectors(np.full((1, 384), np.nan), 1)


def test_persistence_retrieval_filters_and_export(tmp_path):
    frame, _ = load_events([FIXTURE])
    encoder = DeterministicTestEncoder()
    store = LogStore(tmp_path / 'db', encoder.model_name, create=True)
    assert store.index(frame, encoder, batch_size=2)['collection_total'] == 6
    assert store.index(frame, encoder)['collection_total'] == 6
    reopened = LogStore(tmp_path / 'db', encoder.model_name)
    results = reopened.query('powershell', encoder)
    assert len(results) == 5
    assert results[0]['distance_l2_squared'] <= results[-1]['distance_l2_squared']
    assert results[0]['original_event']['synthetic'] is True
    assert results[0]['distance_l2'] ** 2 == pytest.approx(results[0]['distance_l2_squared'])
    filtered = reopened.query('cmd', encoder, [1], '2018-08-20T10:04:00Z', '2018-08-20T10:05:00Z')
    assert len(filtered) == 2
    assert all(row['metadata']['EventID'] == 1 for row in filtered)
    assert reopened.query('x', encoder, [999]) == []
    with pytest.raises(ValueError, match='later'):
        reopened.query('x', encoder, after='2020-01-01', before='2019-01-01')
    with pytest.raises(ValueError, match='configuration'):
        LogStore(tmp_path / 'db', MODEL_NAME)
    json_path, csv_path = export_results(results, tmp_path / 'output/search')
    assert len(json.loads(Path(json_path).read_text())) == 5
    exported = pd.read_csv(csv_path)
    assert len(exported) == 5
    assert json.loads(exported.iloc[0].original_event)['synthetic'] is True
    export_results([], tmp_path / 'output/empty')
    assert len(pd.read_csv(tmp_path / 'output/empty.csv')) == 0


def test_assignment_queries():
    queries = json.loads((FIXTURE.parents[2] / 'config/queries.json').read_text())
    assert len(queries) == 10
    assert len({query['id'] for query in queries}) == 10
    assert all(query['text'].endswith('.') for query in queries)


@pytest.mark.integration
def test_actual_minilm_pipeline(tmp_path):
    """Download real weights and exercise MiniLM with SYNTHETIC input only."""
    encoder = MiniLMEncoder(device='cpu')
    vectors = encoder.encode(['Office application starts a shell', 'Outbound network connection'])
    assert vectors.shape == (2, 384)
    frame, _ = load_events([FIXTURE])
    store = LogStore(tmp_path / 'db', encoder.model_name, create=True)
    assert store.index(frame, encoder, batch_size=2)['indexed_this_run'] == 6
    results = store.query('Office applications launching command shells', encoder)
    assert len(results) == 5
    assert all(np.isfinite(row['distance_l2']) for row in results)
    export_results(results, tmp_path / 'real_model_synthetic_search')


def test_cli_counts_and_exports(tmp_path, monkeypatch, capsys):
    import semantic_logs.__main__ as cli
    encoder = DeterministicTestEncoder()
    encoder.device = 'synthetic-test-double'
    monkeypatch.setattr(cli, 'MiniLMEncoder', lambda device=None: encoder)
    database = str(tmp_path / 'cli_db')
    assert cli.main(['index', str(FIXTURE), '--db', database, '--batch-size', '2']) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary['processed'] == 7
    assert summary['indexed_this_run'] == 6
    output = str(tmp_path / 'results/all')
    assert cli.main(['investigate', '--db', database, '--output', output]) == 0
    results = json.loads(capsys.readouterr().out)
    assert results['summary']['queries_executed'] == 10
    assert results['summary']['matches_returned'] == 50
    assert len(pd.read_csv(output + '.csv')) == 50
    assert len(json.loads(Path(output + '.summary.json').read_text())['queries']) == 10


def test_empty_input_and_invalid_batch(tmp_path, capsys):
    import semantic_logs.__main__ as cli
    path = tmp_path / 'empty.json'
    path.write_text('[]')
    assert cli.main(['index', str(path), '--db', str(tmp_path / 'absent_db')]) == 0
    assert json.loads(capsys.readouterr().out)['indexed_this_run'] == 0
    assert not (tmp_path / 'absent_db').exists()
    frame, _ = load_events([FIXTURE])
    encoder = DeterministicTestEncoder()
    store = LogStore(tmp_path / 'db', encoder.model_name, create=True)
    with pytest.raises(ValueError, match='positive'):
        store.index(frame, encoder, batch_size=0)


def test_clean_invalid_event_ids_and_unix_timestamp(tmp_path):
    path = tmp_path / 'clean.json'
    path.write_text(json.dumps([
        {'EventID': '1.5', 'Image': 'ignored.exe'},
        {'EventID': 'inf', 'Image': 'ignored.exe'},
        {'EventCode': '3', '_time': '1534759260.0', 'Image': 'test.exe'}]))
    frame, stats = load_events([path])
    assert stats['processed'] == 3
    assert stats['filtered'] == 2
    assert frame.iloc[0].timestamp == 1534759260.0
    assert stats['invalid_or_missing_time'] == 0


def test_batch_validation_before_model_loading(tmp_path, capsys):
    import semantic_logs.__main__ as cli
    assert cli.main(['index', str(FIXTURE), '--batch-size', '0']) == 1
    assert 'must be positive' in capsys.readouterr().err
