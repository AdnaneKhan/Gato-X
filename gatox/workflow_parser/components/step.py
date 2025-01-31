"""
Copyright 2024, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re
from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator
from gatox.workflow_parser.utility import decompose_action_ref


class Step:
    """Wrapper class for a Github Actions worflow step."""

    pattern = re.compile(
        r"checkout\s+(\$\{\{)?\s*(\S*([a-z$_]+)\S*)\s*(\}\})?", re.IGNORECASE
    )

    CONTEXT_REGEX = re.compile(r"\${{\s*([^}]+[^\s])\s?\s*}}")

    EVALUATOR = ExpressionEvaluator()

    TYPES = ["RUN", "ACTION"]

    def __init__(self, step_data: dict):
        """Constructor for step wrapper."""
        self.contents = None
        self.step_data = step_data
        # Means that it is a run step or an action that can be injected into.
        # User controlled context + script = vuln.
        self.is_script = False
        # Means that the step checks out code in some way.
        self.is_checkout = False
        # Means that action runs something under control of a checkout
        self.is_sink = False
        # Means that there is some kind of check that would block an external actor.
        self.is_gate = False
        self.evaluated = False
        self.name = "NONE"

        if "name" in self.step_data:
            self.name = self.step_data["name"]

        if "if" in self.step_data:
            if type(self.step_data["if"]) == str:
                self.if_condition = self.step_data["if"].replace("\n", "")
            else:
                self.if_condition = None
        else:
            self.if_condition = None

        if "run" in self.step_data:
            self.contents = self.step_data["run"]
            self.type = "RUN"
            self.is_script = True

            self.__process_run(self.contents)
        elif "uses" in self.step_data:
            self.uses = self.step_data["uses"]
            self.type = "ACTION"

            self.__process_action(self.uses)
        else:
            raise ValueError("Step must have either a 'run' or 'uses' key")

    def __check_sinks(self, contents):
        """Check if the contents contain a sink."""
        sinks = ConfigurationManager().WORKFLOW_PARSING["SINKS"]

        for sink in sinks:
            if sink in contents:
                return True

    def __process_run(self, contents: str):
        """Processes run steps for additional context"""
        if not contents:
            return

        # TODO make a regex for speed
        if "git checkout" in contents or "pr checkout" in contents:
            match = self.pattern.search(contents)
            if match:
                ref = match.group(2)

                static_vals = ["base", "main", "master"]

                for prefix in ConfigurationManager().WORKFLOW_PARSING["PR_ISH_VALUES"]:
                    if prefix in ref.lower() and not any(
                        substring in ref.lower() for substring in static_vals
                    ):
                        self.metadata = ref
                        self.is_checkout = True

        elif self.__check_sinks(contents):
            self.is_sink = True

    def __process_action(self, uses: str):
        """Processes actions referenced by a step to classify it. Currently, Gato-X
        attempts to classify it based on behavior like gating, checkouts, scripts, and sinks.
        """
        if not uses:
            return

        # TODO: programmatically generate a regex from these cases.
        # Custom checkout - capture the params
        if (
            "/checkout" in uses
            and "with" in self.step_data
            and "ref" in self.step_data["with"]
        ):
            ref_param = self.step_data["with"]["ref"]
            # If the ref is not a string, it's not going to reference the PR head.
            if type(ref_param) is not str:
                self.is_checkout = False
            elif "path" in self.step_data["with"]:
                # Custom path means that the checkout probably is not executed.
                self.is_checkout = False
            elif "${{" in ref_param and "base" not in ref_param:
                self.metadata = ref_param
                self.is_checkout = True

        elif "ruby/setup-ruby" in uses and "with" in self.step_data:
            if (
                "bundler-cache" in self.step_data["with"]
                and self.step_data["with"]["bundler-cache"]
            ):
                self.is_sink = True
        elif (
            "gradle-build-action" in uses
            and "with" in self.step_data
            and "arguments" in self.step_data["with"]
        ):
            self.metadata = self.step_data["with"]
        elif (
            "github-script" in uses
            and "with" in self.step_data
            and "script" in self.step_data["with"]
        ):
            self.contents = self.step_data["with"]["script"]
            if (
                "getCollaboratorPermissionLevel" in self.contents
                or "checkMembershipForUser" in self.contents
                or "listMembersInOrg" in self.contents
            ):
                self.is_gate = True

            self.is_script = True
        elif "actions-team-membership" in uses:
            self.is_gate = True
        elif "get-user-teams-membership" in uses:
            self.is_gate = True
        elif "permission" in uses:
            self.is_gate = True
        elif uses.startswith("./"):
            # Local actions are runnable, so it is a sink.
            self.is_sink = True

    def getTokens(self):
        """Get the context tokens from the step."""
        if self.contents:
            finds = self.CONTEXT_REGEX.findall(self.contents)

            extension = None
            for find in finds:
                if " || " in find:
                    extension = find.split(" || ")
                    break

            if extension:
                finds.extend(extension)
            return finds
        else:
            return None

    def getActionParts(self):
        if self.type == "ACTION":
            return

    def evaluateIf(self):
        """Evaluate the If expression by parsing it into an AST
        and then evaluating it in the context of an external user
        triggering it.
        """
        if self.if_condition and not self.evaluated:
            try:
                parser = ExpressionParser(self.if_condition)
                if self.EVALUATOR.evaluate(parser.get_node()):
                    self.if_condition = f"EVALUATED: {self.if_condition}"
                else:
                    self.if_condition = f"RESTRICTED: {self.if_condition}"
            except ValueError as ve:
                # TODO: Remove after alpha.
                self.if_condition = self.if_condition
            except NotImplementedError as ni:
                self.if_condition = self.if_condition
            except (SyntaxError, IndexError) as e:
                self.if_condition = self.if_condition
            finally:
                self.evaluated = True

        return self.if_condition
