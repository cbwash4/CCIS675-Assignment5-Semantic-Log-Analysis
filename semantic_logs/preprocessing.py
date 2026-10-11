"""Read exported events, normalize Sysmon fields, and retain original records."""
import hashlib
import json
import math
import re
from pathlib import Path
import xml.etree.ElementTree as ET

import pandas as pd

FIELDS = ('EventID', 'UtcTime', 'Image', 'ParentImage', 'CommandLine', 'SourceIp',
          'DestinationIp', 'DestinationPort', 'TargetFilename')
ALIASES = {'EventID': ('EventCode', 'event_id', 'event.code'),
           'UtcTime': ('_time', 'TimeCreated', 'timestamp')}


def _records(path):
    if path.suffix.lower() == '.csv':
        return pd.read_csv(path, dtype=str, keep_default_na=False).to_dict('records')
    if path.suffix.lower() == '.jsonl':
        with path.open(encoding='utf-8-sig') as stream:
            values = [json.loads(line) for line in stream if line.strip()]
    elif path.suffix.lower() == '.json':
        with path.open(encoding='utf-8-sig') as stream:
            values = json.load(stream)
        if isinstance(values, dict):
            values = values.get('results', [values])
    else:
        raise ValueError(f'{path}: expected an exported .json, .jsonl, or .csv file; '
                         'Splunk journal.gz and .tsidx files are not event exports')
    if not isinstance(values, list):
        raise ValueError('JSON must contain an event object, array, or results array')
    if any(not isinstance(value, dict) for value in values):
        raise ValueError('Every event must be a JSON object')
    return values


def _flatten(record):
    out = {}
    for key, value in record.items():
        if isinstance(value, dict):
            out.update(_flatten(value))
        else:
            out[key] = value
    return out


def _scalar(value):
    if isinstance(value, list):
        return ' '.join(str(item) for item in value if item is not None)
    return '' if value is None else str(value).strip()


def _fields(record):
    flat = _flatten(record.get('result', record))
    raw = flat.get('_raw')
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
            if isinstance(decoded, dict):
                flat.update(_flatten(decoded))
        except json.JSONDecodeError:
            try:
                root = ET.fromstring(raw)
                for node in root.iter():
                    tag = node.tag.rsplit('}', 1)[-1]
                    if tag == 'Data' and 'Name' in node.attrib:
                        flat[node.attrib['Name']] = node.text
                    elif tag == 'EventID':
                        flat['EventID'] = node.text
                    elif tag == 'TimeCreated':
                        flat['UtcTime'] = node.attrib.get('SystemTime', '')
            except ET.ParseError:
                # Splunk may export rendered key=value text rather than XML.
                for field in FIELDS:
                    match = re.search(rf'(?:^|[\r\n]){field}\s*[:=]\s*([^\r\n]+)', raw)
                    if match:
                        flat[field] = match.group(1)
    lookup = {key.lower(): value for key, value in flat.items()}
    fields = {}
    for field in FIELDS:
        candidates = (field,) + ALIASES.get(field, ())
        fields[field] = next((_scalar(lookup[key.lower()]) for key in candidates
                              if key.lower() in lookup and _scalar(lookup[key.lower()])), '')
    return fields


def load_events(paths, event_ids=(1, 3, 11)):
    """Return a normalized DataFrame plus explicit input/filter counts.

    Use event_ids=None to retain every event, including those without EventID.
    No deduplication silently drops exported records.
    """
    rows = []
    processed = filtered = empty = invalid_time = 0
    for filename in paths:
        path = Path(filename)
        for ordinal, raw in enumerate(_records(path)):
            processed += 1
            fields = _fields(raw)
            try:
                numeric_id = float(fields['EventID'])
                event_id = int(numeric_id) if math.isfinite(numeric_id) and numeric_id.is_integer() else -1
            except (ValueError, OverflowError):
                event_id = -1
            if event_ids is not None and event_id not in event_ids:
                filtered += 1
                continue
            fields['EventID'] = event_id
            narrative = '; '.join(f'{key}: {value}' for key, value in fields.items()
                                  if value != '' and not (key == 'EventID' and value == -1))
            if not narrative:
                fallback = _scalar(_flatten(raw).get('_raw', ''))
                narrative = fallback
            if not narrative:
                empty += 1
                continue
            time_value = fields['UtcTime']
            # Splunk REST exports may represent _time as Unix seconds.
            if re.fullmatch(r'-?\d{9,}(?:\.\d+)?', time_value):
                timestamp = pd.to_datetime(float(time_value), unit='s', utc=True, errors='coerce')
            else:
                timestamp = pd.to_datetime(time_value, utc=True, errors='coerce')
            if pd.isna(timestamp):
                invalid_time += 1
            raw_json = json.dumps(raw, ensure_ascii=False, sort_keys=True, allow_nan=False)
            identity = f'{path.resolve()}:{ordinal}:{raw_json}'
            rows.append({**fields, 'text_payload': narrative, 'raw_json': raw_json,
                         'id': hashlib.sha256(identity.encode()).hexdigest(),
                         'source_file': str(path.resolve()),
                         'timestamp': None if pd.isna(timestamp) else float(timestamp.timestamp())})
    frame = pd.DataFrame(rows, columns=(*FIELDS, 'text_payload', 'raw_json', 'id',
                                       'source_file', 'timestamp'))
    return frame, {'processed': processed, 'selected': len(rows), 'filtered': filtered,
                   'empty': empty, 'invalid_or_missing_time': invalid_time}
