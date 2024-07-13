from gatox.attack.cicd_attack import CICDAttack
from gatox.attack.payloads.payloads import Payloads


def test_create_malicious_push_yaml():
    """Test code to create a malicious yaml file
    """
    yaml = CICDAttack.create_push_yml("whoami", "testing")

    assert "run: whoami" in yaml
