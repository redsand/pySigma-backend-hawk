"""Convert a whole Sigma rule tree to HAWK score records, in-process.

Usage:
    python convert_corpus.py <sigma_repo_root> [--out reports/converted.jsonl] [--dirs rules,rules-emerging-threats,...]

Writes one JSON record per converted rule (plus `_source`, `_status`, `_level`, `_date`,
`_modified`) and a sidecar `<out>.errors.json` listing rules that failed to convert and why.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sigma.backends.hawk import hawkBackend  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.pipelines.hawk import hawk_pipeline  # noqa: E402

DEFAULT_DIRS = ["rules", "rules-emerging-threats", "rules-threat-hunting", "rules-compliance"]


def iter_rule_files(sigma_root: Path, dirs: list[str]):
    for d in dirs:
        base = sigma_root / d
        if not base.is_dir():
            continue
        yield from sorted(base.rglob("*.yml"))


def convert_file(backend: hawkBackend, path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    coll = SigmaCollection.from_yaml(text)
    return backend.convert(coll)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sigma_root")
    ap.add_argument("--out", default=str(Path(__file__).parent / "reports" / "converted.jsonl"))
    ap.add_argument("--dirs", default=",".join(DEFAULT_DIRS))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    sigma_root = Path(args.sigma_root)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    backend = hawkBackend(processing_pipeline=hawk_pipeline())

    n_files = n_ok = 0
    errors: list[dict] = []
    t0 = time.time()
    with out_path.open("w", encoding="utf-8") as fh:
        for path in iter_rule_files(sigma_root, args.dirs.split(",")):
            n_files += 1
            if args.limit and n_files > args.limit:
                break
            rel = str(path.relative_to(sigma_root)).replace("\\", "/")
            try:
                meta = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception as e:  # noqa: BLE001
                errors.append({"file": rel, "stage": "yaml", "error": f"{type(e).__name__}: {e}"})
                continue
            if not isinstance(meta, dict) or "detection" not in meta:
                continue  # correlation-only or non-rule documents
            try:
                records = convert_file(backend, path)
            except Exception as e:  # noqa: BLE001
                errors.append({"file": rel, "stage": "convert", "error": f"{type(e).__name__}: {str(e)[:300]}"})
                continue
            for rec in records:
                rec = dict(rec)
                rec["_source"] = rel
                rec["_status"] = str(meta.get("status") or "")
                rec["_level"] = str(meta.get("level") or "")
                rec["_date"] = str(meta.get("date") or "")
                rec["_modified"] = str(meta.get("modified") or "")
                rec["_title"] = str(meta.get("title") or "")
                if "deprecated" in rel.split("/")[0]:
                    rec["filter_name"] = rec["filter_name"] + " (Deprecated)"
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n_ok += 1
            if n_files % 250 == 0:
                print(f"  {n_files} files, {n_ok} records, {len(errors)} errors, {time.time()-t0:.0f}s", flush=True)

    err_path = out_path.with_suffix(".errors.json")
    err_path.write_text(json.dumps(errors, indent=1), encoding="utf-8")
    print(f"files={n_files} records={n_ok} errors={len(errors)} elapsed={time.time()-t0:.1f}s -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
