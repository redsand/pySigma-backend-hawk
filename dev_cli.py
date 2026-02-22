import argparse
import json
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.pipelines.hawk import hawk_pipeline
from sigma.backends.hawk.hawk import hawkBackend

def gather_rule_files(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise SystemExit(f"input path is not a file or directory: {path}")

    matcher = ("*.yml", "*.yaml")
    glob_method = path.rglob if recursive else path.glob
    files = [p for pattern in matcher for p in glob_method(pattern)]
    return sorted(set(files))


def print_results(file_path: Path, converted: list[dict]) -> None:
    print(f"\n=== {file_path} ===")
    if not converted:
        print("<no conversions produced>")
        return

    for result in converted:
        print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description="HAWK pySigma Backend CLI Tester")
    parser.add_argument("target", help="Path to the Sigma YAML rule or directory")
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively iterate through directories",
    )

    args = parser.parse_args()

    target_path = Path(args.target)
    rule_files = gather_rule_files(target_path, args.recursive)
    if not rule_files:
        raise SystemExit(f"no Sigma rule files found under: {target_path}")

    backend = hawkBackend(processing_pipeline=hawk_pipeline())

    for rule_path in rule_files:
        with rule_path.open("r", encoding="utf-8") as f:
            rule_text = f.read()

        collection = SigmaCollection.from_yaml(rule_text)
        converted = backend.convert(collection)
        print_results(rule_path, converted)

if __name__ == "__main__":
    main()
