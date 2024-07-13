from datetime import datetime
import yaml

from yaml import CSafeLoader
from yaml.resolver import Resolver


# remove resolver entries for On/Off/Yes/No
for ch in "OoTtFf":
    if len(Resolver.yaml_implicit_resolvers[ch]) == 1:
        del Resolver.yaml_implicit_resolvers[ch]
    else:
        Resolver.yaml_implicit_resolvers[ch] = [x for x in
        Resolver.yaml_implicit_resolvers[ch] if x[0] != 'tag:yaml.org,2002:bool']

class Workflow():
    def __init__(
            self, 
            repo_name,
            workflow_contents,
            workflow_name,
            date=None,
            non_default=None,
            special_path=None
        ):
        self.repo_name = repo_name
        self.invalid = False
        self.workflow_name = workflow_name
        self.special_path = special_path
        if non_default:
            self.branch = non_default
        else:
            self.branch = None

        # Only save off if it's a valid parse. RAM matters.
        try:
            if type(workflow_contents) == bytes:
                workflow_contents = workflow_contents.decode(
                    'utf-8'
                )
            self.parsed_yml = yaml.load(
                workflow_contents.replace('\t','  '),
                Loader=CSafeLoader
            )

            if not self.parsed_yml or type(self.parsed_yml) != dict:
                self.invalid = True

            self.workflow_contents = workflow_contents
        except (
            yaml.parser.ParserError,
            yaml.scanner.ScannerError,
            yaml.constructor.ConstructorError
        ) as parse_error:
            self.invalid = True
        except ValueError as parse_error:
            self.invalid = True
        except Exception as parse_error:
            print(
                "Received an exception while parsing workflow contents: " + str(parse_error)
            )
            self.invalid = True

        self.date = date if date else datetime.now().isoformat()

    def isInvalid(self):
        return self.invalid