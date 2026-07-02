#!/usr/bin/env python3
"""
O-Prime - REAL SHACL validation of the semantic artifacts.

Unlike the earlier heuristic checker (evaluation/shacl-validator.mjs, which only
grepped for predicate strings), this runs a full SHACL reasoner (pyshacl) over
the actual RDF artifacts using the shapes in shapes/.

Outputs, per artifact: conforms (bool), #violations, triple count.
Also reports the combined-graph triple total used in the paper.
"""
import sys
import traceback
from pathlib import Path
from rdflib import Graph
from rdflib.namespace import SH

try:
    from pyshacl import validate
except ImportError:
    print("ERROR: pyshacl is not installed. Install with: pip3 install pyshacl", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parent.parent          # o-prime-extended/
EVAL_ROOT = ROOT.parent / "o-prime-eval"               # deployed gateway data

SHAPE_FILES = sorted((ROOT / "shapes").glob("*.ttl"))

# ============================================================================
# ARTIFACT REGISTRY - grouped by category for paper Table X
# ============================================================================
ARTIFACTS = [
    # --- ODRL policies (health + student) ---
    ("count-policy",         "ODRL policies",      ROOT / "policies/count-policy.ttl"),
    ("purpose-policy",       "ODRL policies",      ROOT / "policies/purpose-policy.ttl"),
    ("legal-basis-policy",   "ODRL policies",      ROOT / "policies/legal-basis-policy.ttl"),
    ("temporal-policy",      "ODRL policies",      ROOT / "policies/temporal-policy.ttl"),
    ("recipient-policy",     "ODRL policies",      ROOT / "policies/recipient-policy.ttl"),
    ("duty-policy",          "ODRL policies",      ROOT / "policies/duty-policy.ttl"),

    # --- PROV-O audit logs (health + student) ---
    ("sample-access-log",    "PROV-O audit logs",  ROOT / "logs/sample-access-log.ttl"),

    # --- DPV mapping layer (health + student) ---
    ("dpv-mapping",          "DPV mapping layer",  ROOT / "dpv/dpv-mapping.ttl"),

    # --- State-of-the-World (health + student) ---
    ("sample-sotw",          "State-of-the-World", ROOT / "sotw/sample-sotw.ttl"),
]


def load_shapes() -> Graph:
    """Load all SHACL shapes from shapes/ directory."""
    g = Graph()
    for sf in SHAPE_FILES:
        try:
            g.parse(sf, format="turtle")
            print(f"  ✓ Loaded shape: {sf.name}")
        except Exception as e:
            print(f"  ✗ ERROR loading {sf.name}: {e}", file=sys.stderr)
            raise
    return g


def validate_artifact(data: Graph, shapes: Graph):
    """Validate a single artifact and return (conforms, violations, triples)."""
    try:
        conforms, report_graph, _ = validate(
            data, shacl_graph=shapes, inference="none",
            abort_on_first=False, meta_shacl=False, advanced=True,
        )
        violations = len(list(report_graph.subject_objects(SH.resultSeverity)))
        return conforms, violations, len(data)
    except Exception as e:
        print(f"  ⚠️  Validation error: {e}", file=sys.stderr)
        traceback.print_exc()
        return False, -1, len(data)


def main() -> int:
    print(f"Loading {len(SHAPE_FILES)} shape files...")
    shapes = load_shapes()
    print(f"Total: {len(shapes)} shape triples\n")

    # Per-artifact validation
    rows = []  # (label, category, conforms, violations, triples)
    for label, category, path in ARTIFACTS:
        if not path.exists():
            print(f"⚠️  Missing artifact: {path}", file=sys.stderr)
            rows.append((label, category, False, -1, 0))
            continue
        data = Graph()
        try:
            data.parse(path, format="turtle")
        except Exception as e:
            print(f"⚠️  Could not parse {path.name}: {e}", file=sys.stderr)
            rows.append((label, category, False, -1, 0))
            continue
        conforms, violations, triples = validate_artifact(data, shapes)
        rows.append((label, category, conforms, violations, triples))

    # Combined graph validation
    combined = Graph()
    for label, category, path in ARTIFACTS:
        if not path.exists():
            continue
        data = Graph()
        try:
            data.parse(path, format="turtle")
            combined += data
        except Exception as e:
            print(f"⚠️  Could not parse {path.name}: {e}", file=sys.stderr)

    c_conf, c_rep, _ = validate(combined, shacl_graph=shapes,
                                inference="none", advanced=True)
    c_viol = len(list(c_rep.subject_objects(SH.resultSeverity)))

    # ========================================================================
    # AGGREGATE BY CATEGORY (for paper table)
    # ========================================================================
    categories = {}
    for label, category, conforms, violations, triples in rows:
        if category not in categories:
            categories[category] = {"triples": 0, "violations": 0, "all_conform": True}
        categories[category]["triples"] += triples
        categories[category]["violations"] += violations
        if not conforms:
            categories[category]["all_conform"] = False

    # Combined graph entry
    categories["Combined graph"] = {
        "triples": len(combined),
        "violations": c_viol,
        "all_conform": c_conf,
    }

    # ========================================================================
    # PRINT TABLE (paper-ready format)
    # ========================================================================
    col_artifact = 42
    col_triples = 8
    col_conforms = 9

    header = (
        f"{'Artifact':<{col_artifact}}"
        f"{'Triples':>{col_triples}}"
        f"{'Conforms':>{col_conforms}}"
    )
    sep = "-" * (col_artifact + col_triples + col_conforms)

    print()
    print(header)
    print(sep)

    # Print category rows
    for cat_name in ["ODRL policies", "PROV-O audit logs", "DPV mapping layer",
                     "State-of-the-World", "Combined graph"]:
        if cat_name not in categories:
            continue
        cat = categories[cat_name]
        mark = "✓" if cat["all_conform"] else "✗"
        print(
            f"{cat_name + ' (health + student)':<{col_artifact}}"
            f"{cat['triples']:>{col_triples}}"
            f"{mark:>{col_conforms}}"
        )

    print(sep)

    # ========================================================================
    # DETAILED PER-ARTIFACT BREAKDOWN (for debugging)
    # ========================================================================
    print("\nDetailed per-artifact breakdown:")
    print(f"{'artifact':<30} {'result':<6} {'viol':>5} {'triples':>8}")
    print("-" * 55)
    for label, category, conforms, violations, triples in rows:
        res = "PASS" if conforms else "FAIL"
        v_str = str(violations) if violations >= 0 else "MISSING"
        print(f"{label:<30} {res:<6} {v_str:>5} {triples:>8}")

    # ========================================================================
    # SUMMARY
    # ========================================================================
    n_pass = sum(1 for r in rows if r[2])
    n_total = len(rows)
    total_viol = sum(r[3] for r in rows if r[3] >= 0)

    print(f"\nTOTAL: {n_pass}/{n_total} artifacts pass, "
          f"{total_viol} violations, {len(combined)} combined triples")
    print(f"Combined graph: {len(combined)} triples, "
          f"conforms={c_conf}, violations={c_viol}")

    # Exit code: 0 if all pass, 1 otherwise
    return 0 if (n_pass == n_total and c_conf) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(2)