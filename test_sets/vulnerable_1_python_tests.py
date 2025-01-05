import unittest
import pickle
import json
from mitigated_files.vulnerable_1_mitigated import load_user_data as mitigated_load
from vulnerable_files.python.vulnerable_1 import load_user_data as vulnerable_load

class TestLoadUserData(unittest.TestCase):
    def setUp(self):
        self.test_data = {'username': 'johndoe', 'email': 'johndoe@example.com', 'roles': ['user', 'admin']}
        self.expected_output = self.test_data

        # Serialized inputs
        self.serialized_pickle_data = pickle.dumps(self.test_data)
        self.serialized_json_data = json.dumps(self.test_data)

    def test_vulnerable_script(self):
        result = vulnerable_load(self.serialized_pickle_data)
        self.assertEqual(result, self.expected_output)

    def test_mitigated_script(self):
        result = mitigated_load(self.serialized_json_data)
        self.assertEqual(result, self.expected_output)

if __name__ == '__main__':
    unittest.main()
