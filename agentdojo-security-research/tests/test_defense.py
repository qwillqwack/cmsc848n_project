import unittest
from defense.rules import RuleChecker
from defense.classifier import IntentClassifier
from defense.hybrid import HybridDefense

class TestDefense(unittest.TestCase):

    def setUp(self):
        self.rule_checker = RuleChecker()
        self.intent_classifier = IntentClassifier()
        self.hybrid_defense = HybridDefense()

    def test_rule_checker_valid_case(self):
        # Test a valid case for the rule checker
        user_request = "Pay the bill to IBAN DE89 3704 ..."
        proposed_call = {"recipient": "DE89 3704 ...", "amount": 98.70}
        result = self.rule_checker.check(proposed_call, user_request)
        self.assertTrue(result)

    def test_rule_checker_invalid_case(self):
        # Test an invalid case for the rule checker
        user_request = "Pay the bill to IBAN DE89 3704 ..."
        proposed_call = {"recipient": "GB29 NWBK ...", "amount": 98.70}
        result = self.rule_checker.check(proposed_call, user_request)
        self.assertFalse(result)

    def test_intent_classifier_valid_case(self):
        # Test a valid case for the intent classifier
        user_request = "Send $100 to Alice"
        proposed_call = {"recipient": "Alice", "amount": 100}
        result = self.intent_classifier.evaluate(proposed_call, user_request)
        self.assertEqual(result, "allow")

    def test_intent_classifier_invalid_case(self):
        # Test an invalid case for the intent classifier
        user_request = "Send $100 to Alice"
        proposed_call = {"recipient": "Bob", "amount": 100}
        result = self.intent_classifier.evaluate(proposed_call, user_request)
        self.assertEqual(result, "block")

    def test_hybrid_defense_valid_case(self):
        # Test a valid case for the hybrid defense
        user_request = "Pay the bill to IBAN DE89 3704 ..."
        proposed_call = {"recipient": "DE89 3704 ...", "amount": 98.70}
        result = self.hybrid_defense.evaluate(proposed_call, user_request)
        self.assertTrue(result)

    def test_hybrid_defense_invalid_case(self):
        # Test an invalid case for the hybrid defense
        user_request = "Pay the bill to IBAN DE89 3704 ..."
        proposed_call = {"recipient": "GB29 NWBK ...", "amount": 98.70}
        result = self.hybrid_defense.evaluate(proposed_call, user_request)
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()