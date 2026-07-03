#!/usr/bin/env python3
"""
O-Prime - SPARQL Query Validation

Validates all 15 SPARQL competency questions (cq1-*.rq to cq14-*.rq) against
the sample PROV-O audit log (logs/access-log.ttl).

For each query, reports:
  - Parse status (syntax valid?)
  - Execution status (runs without error?)
  - Result count (how many rows returned?)
  - Sample result (first row, if any)

This complements the master-eval.mjs orchestrator by providing detailed
query-level diagnostics.
"""
import sys
import traceback
from pathlib import Path
from rdflib import Graph
from rdflib.plugins.sparql import prepareQuery
from rdflib.plugins.sparql.processor import SPARQLResult

ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = ROOT / "logs" / "access-log.ttl"
SPARQL_DIR = ROOT / "sparql"


def load_audit_log() -> Graph:
    """Load the sample PROV-O audit log."""
    if not LOG_FILE.exists():
        print(f"Audit log not found: {LOG_FILE}", file=sys.stderr)
        sys.exit(1)
    g = Graph()
    g.parse(LOG_FILE, format="turtle")
    print(f"✓ Loaded audit log: {len(g)} triples from {LOG_FILE.name}\n")
    return g


def validate_query(graph: Graph, query_path: Path) -> dict:
    """
    Validate a single SPARQL query.
    Returns: {
        'file': str,
        'parse_ok': bool,
        'execute_ok': bool,
        'result_count': int,
        'sample_row': list | None,
        'error': str | None,
    }
    """
    result = {
        'file': query_path.name,
        'parse_ok': False,
        'execute_ok': False,
        'result_count': 0,
        'sample_row': None,
        'error': None,
    }

    try:
        query_text = query_path.read_text()
    except Exception as e:
        result['error'] = f"Cannot read file: {e}"
        return result

    # Step 1: Parse the query
    try:
        prepared = prepareQuery(query_text)
        result['parse_ok'] = True
    except Exception as e:
        result['error'] = f"Parse error: {e}"
        return result

    # Step 2: Execute the query
    try:
        exec_result = graph.query(query_text)
        result['execute_ok'] = True
    except Exception as e:
        result['error'] = f"Execution error: {e}"
        return result

    # Step 3: Count results and extract sample
    try:
        rows = list(exec_result)
        result['result_count'] = len(rows)
        if rows:
            # Convert rdflib terms to Python strings for display
            result['sample_row'] = [str(v) for v in rows[0]]
    except Exception as e:
        result['error'] = f"Result iteration error: {e}"
        return result

    return result


def main() -> int:
    graph = load_audit_log()

    # ✅ FIXED: Find all cq*.rq files (cq1-*.rq, cq2-*.rq, etc.)
    query_files = sorted(SPARQL_DIR.glob("cq*.rq"))
    if not query_files:
        print(f"No cq*.rq files found in {SPARQL_DIR}", file=sys.stderr)
        return 1

    print(f"Found {len(query_files)} SPARQL queries to validate:\n")

    # Validate each query
    results = []
    for qf in query_files:
        res = validate_query(graph, qf)
        results.append(res)

    # ========================================================================
    # PRINT RESULTS TABLE
    # ========================================================================
    col_file = 32
    col_parse = 8
    col_exec = 8
    col_rows = 8
    col_status = 10

    header = (
        f"{'Query':<{col_file}}"
        f"{'Parse':>{col_parse}}"
        f"{'Exec':>{col_exec}}"
        f"{'Rows':>{col_rows}}"
        f"{'Status':>{col_status}}"
    )
    sep = "-" * (col_file + col_parse + col_exec + col_rows + col_status)

    print(header)
    print(sep)

    parse_pass = 0
    exec_pass = 0
    has_results = 0

    for r in results:
        parse_mark = "✓" if r['parse_ok'] else "✗"
        exec_mark = "✓" if r['execute_ok'] else "✗"

        if r['parse_ok']:
            parse_pass += 1
        if r['execute_ok']:
            exec_pass += 1
        if r['execute_ok'] and r['result_count'] > 0:
            has_results += 1

        # Status determination
        if not r['parse_ok']:
            status = "PARSE_ERR"
        elif not r['execute_ok']:
            status = "EXEC_ERR"
        elif r['result_count'] == 0:
            status = "EMPTY"
        else:
            status = "PASS"

        print(
            f"{r['file']:<{col_file}}"
            f"{parse_mark:>{col_parse}}"
            f"{exec_mark:>{col_exec}}"
            f"{r['result_count']:>{col_rows}}"
            f"{status:>{col_status}}"
        )

        # Print error if any
        if r['error']:
            print(f"   {r['error']}")

    print(sep)

    # ========================================================================
    # SAMPLE RESULTS (for queries that returned data)
    # ========================================================================
    print("\n" + "=" * 70)
    print("SAMPLE RESULTS (first row of each passing query):")
    print("=" * 70)

    for r in results:
        if r['execute_ok'] and r['sample_row']:
            print(f"\n📄 {r['file']} ({r['result_count']} rows):")
            print(f"   First row: {r['sample_row']}")

    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total queries     : {len(results)}")
    print(f"  Parse success     : {parse_pass}/{len(results)}")
    print(f"  Execute success   : {exec_pass}/{len(results)}")
    print(f"  With results      : {has_results}/{len(results)}")
    print(f"  Empty results     : {exec_pass - has_results}/{len(results)}")
    print(f"  Failed            : {len(results) - exec_pass}/{len(results)}")

    # Exit code: 0 if all pass with results, 1 otherwise
    if parse_pass == len(results) and exec_pass == len(results) and has_results == len(results):
        print("\n All queries validated successfully with non-empty results.")
        return 0
    else:
        print("\n Some queries need attention (see above).")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"\n FATAL ERROR: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(2)