import pytest
import os
import pathlib

from unittest.mock import patch, ANY, mock_open

from gato.workflow_parser import WorkflowParser
from gato.workflow_parser.utility import check_sus

TEST_WF = """
name: 'Test WF'

on:
  pull_request:
  workflow_dispatch:

jobs:
  test:
    runs-on: ['self-hosted']
    steps:

    - name: Execution
      run: |
          echo "Hello World and bad stuff!"
"""

TEST_WF2 = """
name: 'Test WF2'

on:
  pull_request_target:

jobs:
  test:
    runs-on: 'ubuntu-latest'
    steps:
    - name: Execution
      uses: actions/checkout@v4
      with:
        ref: ${{ github.event.pull_request.head.ref }}
"""



def test_parse_workflow():

    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')

    sh_list = parser.self_hosted()

    assert len(sh_list) > 0


def test_workflow_write():

    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')

    curr_path = pathlib.Path(__file__).parent.resolve()
    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    with patch("builtins.open", mock_open(read_data="")) as mock_file:
        parser.output(test_repo_path)

        mock_file().write.assert_called_once_with(
            parser.raw_yaml
        )

def test_check_injection_no_vulnerable_triggers():
    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')
    with patch.object(parser, 'get_vulnerable_triggers', return_value=[]):
        result = parser.check_injection()
        assert result == {}

def test_check_injection_no_job_contents():
    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')
    with patch.object(parser, 'get_vulnerable_triggers', return_value=['pull_request']):
        with patch.object(parser, 'extract_step_contents', return_value={}):
            result = parser.check_injection()
            assert result == {}

def test_check_injection_no_step_contents():
    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')
    with patch.object(parser, 'get_vulnerable_triggers', return_value=['pull_request']):
        with patch.object(parser, 'extract_step_contents', return_value={'job1': {'check_steps': [{'contents': None, 'step_name': 'step1'}]}}):
            result = parser.check_injection()
            assert result == {}

def test_check_injection_no_tokens():
    parser = WorkflowParser(TEST_WF, 'unit_test', 'main.yml')
    with patch.object(parser, 'get_vulnerable_triggers', return_value=['pull_request']):
        with patch.object(parser, 'extract_step_contents', return_value={'job1': {'check_steps': [{'contents': None, 'step_name': 'step1'}]}}):
            result = parser.check_injection()
            assert result == {}

def test_check_pwn_request():
    parser = WorkflowParser(TEST_WF2, 'unit_test', 'main.yml')
    result = parser.check_pwn_request()
    assert result['candidates']