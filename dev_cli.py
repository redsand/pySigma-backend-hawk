import argparse
import json
from sigma.parser import SigmaCollectionParser
from sigma.configuration import SigmaConfiguration
from pysigma_hawk_backend.hawk_backend import HawkBackend  

def main():
    parser = argparse.ArgumentParser(description="HAWK pySigma Backend CLI Tester")
    parser.add_argument("rulefile", help="Path to the Sigma YAML rule")

    args = parser.parse_args()

    with open(args.rulefile, "r") as f:
        rule_text = f.read()

    config = SigmaConfiguration()
    rules = SigmaCollectionParser(rule_text, config).rules
    backend = HawkBackend(config)

    for rule in rules:
        result = backend.convert(rule)
        print(json.dumps(json.loads(result), indent=2))

if __name__ == "__main__":
    main()
