# Retrieval Benchmark Certification Gate

- Gate: benchmark
- Status: BLOCKED (prerequisites unavailable)
- Dataset configured: semantic-indexing-prototype
- Modes configured: dense, hybrid-ready
- Measured benchmark cases and metrics: not run

## Blocking prerequisites

- `nonProductionConfirmed`: false
- benchmark cases file missing: `C:\stage-data\semantic-indexing\benchmark-cases.json`
- corpus records file missing: `C:\stage-data\semantic-indexing\corpus-records.jsonl`
- FAISS index file missing: `C:\stage-data\semantic-indexing\index\semantic-index.faiss`
- embedding auth source unavailable at runtime: `env:STAGE_EMBEDDING_API_KEY`

## Rationale

The benchmark gate requires measured dense and hybrid-ready retrieval results produced from real non-production inputs. Required benchmark inputs and embedding auth were unavailable, so benchmark execution did not run and no measured metrics were produced. Unit-test success is not measured benchmark evidence.

## Additional notes

- External injection-pattern configuration: unavailable; conservative built-in defaults active; external file not validated.
- Retrieved content classification: untrusted-reference-material.
- Production deployment performed: False.
