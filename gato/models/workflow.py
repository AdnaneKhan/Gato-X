from datetime import datetime

class Workflow():
    def __init__(self, repo_name, workflow_contents, workflow_name, date=None):
        self.repo_name = repo_name
        if type(workflow_contents) == bytes:
            self.workflow_contents = workflow_contents.decode('utf-8')
        else:
            self.workflow_contents = workflow_contents
        self.workflow_name = workflow_name
        self.date = date if date else datetime.now().isoformat()