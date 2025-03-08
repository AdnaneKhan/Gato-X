import pytest

from gatox import main


def test_cli_double_proxy(capfd):
    """Test case where no arguments are provided."""
    with pytest.raises(SystemExit):
        main.entry()

    out, err = capfd.readouterr()
    assert "are required: command" in err
