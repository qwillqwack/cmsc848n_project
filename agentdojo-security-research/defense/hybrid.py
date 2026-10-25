class HybridDefense:
    def __init__(self, rules_checker, intent_classifier):
        self.rules_checker = rules_checker
        self.intent_classifier = intent_classifier

    def check_call(self, user_request, tool_call):
        # First, apply the rules checker
        rules_result = self.rules_checker.check(tool_call)

        if rules_result == "block":
            return "block"
        elif rules_result == "ask":
            return "ask"

        # If rules allow, use the intent classifier
        classifier_result = self.intent_classifier.evaluate(user_request, tool_call)

        return classifier_result

    def explain_decision(self, user_request, tool_call):
        rules_explanation = self.rules_checker.explain(tool_call)
        classifier_explanation = self.intent_classifier.explain(user_request, tool_call)

        return {
            "rules_explanation": rules_explanation,
            "classifier_explanation": classifier_explanation
        }