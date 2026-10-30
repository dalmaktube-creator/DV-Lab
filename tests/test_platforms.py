import unittest
from dvlab.setup import validate_platform

class Platforms(unittest.TestCase):
    def test_hub_supports_jammy(self):validate_platform('ID=ubuntu\nVERSION_ID="22.04"\n','hub')
    def test_hub_supports_noble(self):validate_platform('ID=ubuntu\nVERSION_ID="24.04"\n','hub')
    def test_agent_supports_noble(self):validate_platform('ID=ubuntu\nVERSION_ID="24.04"\n','agent')
    def test_agent_supports_jammy(self):
        validate_platform('ID=ubuntu\nVERSION_ID="22.04"\n','agent')
    def test_unknown_distro_or_role_is_rejected(self):
        for text,role in [('ID=debian\nVERSION_ID="12"','hub'),('ID=ubuntu\nVERSION_ID="20.04"','hub'),('ID=ubuntu\nVERSION_ID="22.04"','root-shell')]:
            with self.subTest(text=text,role=role),self.assertRaises(SystemExit):validate_platform(text,role)
