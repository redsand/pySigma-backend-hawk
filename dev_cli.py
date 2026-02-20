import argparse
import json
from sigma.collection import SigmaCollection
from sigma.pipelines.hawk import hawk_pipeline
from sigma.backends.hawk.hawk import hawkBackend

def main():
    parser = argparse.ArgumentParser(description="HAWK pySigma Backend CLI Tester")
    parser.add_argument("rulefile", help="Path to the Sigma YAML rule")

    args = parser.parse_args()

    with open(args.rulefile, "r") as f:
        rule_text = f.read()

    collection = SigmaCollection.from_yaml(rule_text)
    backend = hawkBackend(processing_pipeline=hawk_pipeline())
    converted = backend.convert(collection)

    for result in converted:
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
