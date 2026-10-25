def is_literal(value):
    return isinstance(value, str) and value.strip() != ""

def is_structured_source(value):
    return isinstance(value, dict) and all(is_literal(v) for v in value.values())

def check_argument(value, source):
    if is_literal(value):
        return "Literal check passed"
    elif is_structured_source(source):
        return "Structured source check passed"
    else:
        return "Check failed"

def apply_rules(arguments, sources):
    results = {}
    for arg, source in zip(arguments, sources):
        results[arg] = check_argument(arg, source)
    return results

# Example usage
if __name__ == "__main__":
    arguments = ["GB29 NWBK 60161331926819", {"amount": 98.70}]
    sources = ["user request", {"field": "Pay to"}]
    print(apply_rules(arguments, sources))