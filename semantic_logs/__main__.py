import argparse
import json
from pathlib import Path
import sys

from chromadb.errors import NotFoundError

from .embeddings import MiniLMEncoder
from .preprocessing import load_events
from .store import LogStore, export_results


def parser():
    app = argparse.ArgumentParser(description='MiniLM semantic event retrieval (not attack classification)')
    sub = app.add_subparsers(dest='command', required=True)
    for name in ('index', 'query', 'investigate'):
        command = sub.add_parser(name)
        command.add_argument('--db', default='./forensic_db')
        command.add_argument('--device', default=None, help='cpu, cuda, or automatic if omitted')
        if name == 'index':
            command.add_argument('files', nargs='+')
            command.add_argument('--event-ids', type=int, nargs='+', default=[1, 3, 11])
            command.add_argument('--all-events', action='store_true')
            command.add_argument('--batch-size', type=int, default=64)
        else:
            command.add_argument('--event-ids', type=int, nargs='+')
            command.add_argument('--after', help='Inclusive UTC lower time bound (ISO 8601)')
            command.add_argument('--before', help='Inclusive UTC upper time bound (ISO 8601)')
            command.add_argument('--output', default='results/search' if name == 'query' else 'results/investigations')
            if name == 'query':
                command.add_argument('text')
            else:
                command.add_argument('--queries', default=str(Path(__file__).resolve().parent.parent / 'config/queries.json'))
    return app


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == 'index':
            if args.batch_size < 1:
                raise ValueError('--batch-size must be positive')
            frame, counts = load_events(args.files, None if args.all_events else args.event_ids)
            if frame.empty:
                print(json.dumps({**counts, 'indexed_this_run': 0, 'message': 'No eligible events; no model or DB created'}))
                return 0
            encoder = MiniLMEncoder(args.device)
            store = LogStore(args.db, encoder.model_name, create=True)
            stats = store.index(frame, encoder, args.batch_size)
            print(json.dumps({**counts, **stats, 'device': encoder.device}))
        else:
            encoder = MiniLMEncoder(args.device)
            store = LogStore(args.db, encoder.model_name)
            queries = [{'id': 'custom', 'text': args.text}] if args.command == 'query' else json.loads(Path(args.queries).read_text())
            results, summaries = [], []
            for query in queries:
                matches = store.query(query['text'], encoder, args.event_ids, args.after, args.before)
                results.extend({'query_id': query['id'], 'query': query['text'], **match} for match in matches)
                summaries.append({'query_id': query['id'], 'query': query['text'], 'returned': len(matches)})
            exports = export_results(results, args.output)
            summary = {'collection_total': store.collection.count(), 'queries_executed': len(queries),
                       'matches_returned': len(results), 'unique_events_returned': len({r['id'] for r in results}),
                       'queries': summaries, 'exports': exports,
                       'interpretation': 'Semantic similarity alone does not establish malicious behavior.'}
            Path(args.output + '.summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
            print(json.dumps({'summary': summary, 'results': results}, indent=2))
    except (ValueError, OSError, json.JSONDecodeError, NotFoundError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
