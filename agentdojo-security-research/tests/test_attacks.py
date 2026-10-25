import unittest
from attacks.binding_steering import BindingSteeringAttack
from attacks.adaptive_search import AdaptiveSearchAttack

class TestAttacks(unittest.TestCase):

    def setUp(self):
        self.binding_attack = BindingSteeringAttack()
        self.adaptive_attack = AdaptiveSearchAttack()

    def test_binding_steering_attack(self):
        # Example test case for binding steering attack
        result = self.binding_attack.execute_attack()
        self.assertTrue(result['success'], "Binding steering attack should succeed")

    def test_adaptive_search_attack(self):
        # Example test case for adaptive search attack
        result = self.adaptive_attack.execute_attack()
        self.assertTrue(result['success'], "Adaptive search attack should succeed")

if __name__ == '__main__':
    unittest.main()