import tempfile
import os
import subprocess
import logging
import hashlib

from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)


class Git:
    """This class is utilized to perfome a clone of a git repository using a
    PAT (sparse or otherwise) in order to perform deeper analysis on the
    repository content.
    """

    def __init__(
        self,
        pat,
        repo_name: str,
        username="Gato-X",
        email="gato-x@pwn.com",
        proxies=None,
        github_url="github.com",
    ):
        """Initialize the git abstraction class. This class managed a
        checked-out git repository located in a temporary directory.

        The directory is cleaned up upon object destruction, or can be manually
        cleaned up using a delete command.

        Args:
            pat (str): GitHub personal access token with necessary scopes.
            repo_name (str): Name of repository to interact with.
            username (str, optional): Username for the git commit
            email (str, optional): Email for the git commit
            http_proxy (str, optional): Clone through an HTTP proxy.
            Defaults to None.
            socks_proxy (str, optional): Clone through a SOCKS proxy.
            Defaults to None.
        """
        self.cloned = False
        if not github_url:
            self.github_url = "github.com"
        else:
            self.github_url = github_url

        if self.github_url != "github.com" or proxies:
            os.environ["GIT_SSL_NO_VERIFY"] = "True"

        if proxies:
            os.environ["ALL_PROXY"] = proxies["https"]

        self.clone_comamnd = (
            "git clone --depth 1 --filter=blob:none --sparse"
            f" https://{pat}@{self.github_url}/{repo_name}"
        )

        self.config_command1 = f"git config user.name '{username}'"

        self.config_command2 = f"git config user.email '{email}'"

        if len(repo_name.split("/")) != 2:
            raise ValueError("Repository name but be in Org/Repo format!")
        self.repo_name = repo_name

    def __run_command(self, command):
        """ """
        p = subprocess.Popen(
            command.split(" "),
            cwd=self.temp_folder.name,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        output, error = p.communicate()
        return output.decode("utf-8"), error.decode("utf-8")

    def __get_last_commit_date(self, branch):
        output, _ = self.__run_command(f"git log -1 --format=%cd --date=short {branch}")
        return output.strip()

    def __get_file_hash(self, file_path):
        with open(os.path.join(self.temp_folder.name, file_path), "rb") as file:
            file_hash = hashlib.sha256(file.read()).hexdigest()
        return file_hash

    def get_non_default(self):
        """
        Identifies and returns a list of branches containing .yml or .yaml files in the .github/workflows directory
        that use the 'pull_request_target' event and do not match the file hash of the same file in the main branch.
        This is used to find potential security risks in GitHub Actions workflows across all branches except the main branch.

        The method performs the following steps:
        1. Initializes a temporary git repository and configures it for sparse checkout to only include .yml and .yaml files.
        2. Fetches the default branch of the remote repository and checks it out.
        3. Pulls the latest changes from the main branch and collects the hashes of all .yml files in the .github/workflows directory.
        4. Iterates over all branches (except the main branch), checking out each branch and:
        a. Collects the last commit date.
        b. Searches for .yml or .yaml files that contain the 'pull_request_target' event.
        c. Compares the hash of each file against the hash of the same file in the main branch to ensure they are different.
        d. Checks if the file does not include '/checkout' action, indicating a potential security risk.
        e. Collects information about branches that match the criteria, including the branch name, file path, file content, and last commit date.

        Returns:
            A list of tuples, each containing:
            - The branch name
            - The file path of the .yml or .yaml file
            - The content of the file
            - The date of the last commit for the branch

        Note:
            This method uses a temporary directory for the git operations and cleans up after itself.
            It also handles exceptions by printing an error message but does not stop execution.
        """
        self.temp_folder = tempfile.TemporaryDirectory()
        self.__run_command("git init")
        # Add the remote repository
        self.__run_command(
            f"git remote add origin https://{self.github_url}/{self.repo_name}.git"
        )

        # Enable sparse checkout
        self.__run_command("git config core.sparseCheckout true")

        self.__run_command("git config submodule.recurse false")
        self.__run_command("git config index.sparse true")
        self.__run_command("git sparse-checkout init --sparse-index")
        self.__run_command('git sparse-checkout set "**/*.yml **/*.yaml"')
        # Create the sparse-checkout file
        with open(
            os.path.join(self.temp_folder.name, ".git/info/sparse-checkout"), "w"
        ) as file:
            file.write(".github/workflows")

        self.__run_command("git fetch --no-tags --depth 1 --filter=blob:none")
        def_branch = self.__run_command(
            "git remote show origin | grep 'HEAD branch' | cut -d' ' -f5"
        )[0].replace("\n", "")
        self.__run_command(f"git checkout {def_branch}")

        # Dictionary to store file hashes from the main branch
        main_file_hashes = {}
        # just get main
        self.__run_command("git pull")
        # Get the file hashes from the main branch
        output, _ = self.__run_command("git ls-files .github/workflows/*.yml")
        yml_files = output.split("\n")
        for file in yml_files:
            if file:
                main_file_hashes[file] = self.__get_file_hash(file)

        # Get the list of all branches
        output, _ = self.__run_command("git branch -r")
        branches = [branch.strip() for branch in output.split("\n") if branch.strip()]
        hash_cache = set()
        values = []
        # Iterate over each branch
        for branch in branches:
            # Skip the main branch
            if branch == f"origin/{def_branch}":
                continue

            # Checkout the branch
            self.__run_command(f"git checkout {branch}")
            # Get the date of the last commit for the branch
            last_commit_date = self.__get_last_commit_date(branch)
            # Check if the branch contains a .yml file with pull_request_target
            output, _ = self.__run_command("git ls-files .github/workflows/*.yml")
            output2, _ = self.__run_command("git ls-files .github/workflows/*.yaml")
            yml_files = output.split("\n")
            yml_files.extend(output2.split("\n"))

            for file in yml_files:
                if file:
                    with open(os.path.join(self.temp_folder.name, file), "r") as f:
                        content = f.read()
                        if "pull_request_target" in content:
                            try:
                                file_hash = self.__get_file_hash(file)
                                if file_hash == main_file_hashes.get(file):
                                    continue

                                if file_hash not in hash_cache:
                                    hash_cache.add(file_hash)
                                else:
                                    # Only report once per hash
                                    continue

                                if "/checkout" not in content:
                                    continue

                                candidate = Workflow(
                                    self.repo_name,
                                    content,
                                    file,
                                    default_branch=def_branch,
                                    non_default=branch,
                                )

                                if candidate.isInvalid():
                                    continue

                                if (
                                    "on" in candidate.parsed_yml
                                    and "pull_request_target"
                                    in candidate.parsed_yml["on"]
                                ):
                                    vals = candidate.parsed_yml["on"][
                                        "pull_request_target"
                                    ]
                                    if not vals or "branches" not in vals:
                                        values.append(candidate)
                                    elif vals and "branches" in vals:
                                        branch_matchers = vals["branches"]
                                        for br in branch_matchers:
                                            if (
                                                br.replace("*", "", 2)
                                                in branch.split("/")[-1]
                                            ):
                                                values.append(candidate)
                            except Exception:
                                # We really shouldn't get here, but
                                # we don't want to crash enum.
                                pass
        return values

    def perform_clone(self):
        """Performs the actual git clone operation.

        Returns:
            bool: True if the git clone operation was successful, False
            otherwise.
        """

        self.temp_folder = tempfile.TemporaryDirectory()

        try:
            new_wd = self.repo_name.split("/")[1]

            p = subprocess.Popen(
                self.clone_comamnd.split(" "),
                cwd=self.temp_folder.name,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

            if p.returncode != 0:
                logger.error("Git clone operation did not succeed!")
                raise Exception("Git clone operation did not suceeed!")

            p = subprocess.Popen(
                self.config_command1.split(" "),
                cwd=os.path.join(self.temp_folder.name, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

            p = subprocess.Popen(
                self.config_command2.split(" "),
                cwd=os.path.join(self.temp_folder.name, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

            p1 = subprocess.Popen(
                "git sparse-checkout set .github".split(" "),
                cwd=os.path.join(self.temp_folder.name, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p1.wait()

            if p1.returncode != 0:
                logger.error("Git checkout operation did not succeed!")
                raise Exception("Git checkout operation did not suceeed!")
            self.cloned = True

        except Exception as e:
            logging.error(f"Exception during git clone of {self.repo_name}!")
            logging.error(f"Exception details: {str(e)}")
            if self.temp_folder:
                self.temp_folder.cleanup()
            return False

        return self.cloned

    def extract_workflow_ymls(self, repo_path: str = None):
        """Extracts and returns all github workflow .yml files located within
        the cloned repository.

        Args:
            repo_path (str, optional): Path on disk to repository to extract
            workflow yml files from. Defaults to repository associated with
            this object. Parameter intended for future uses and unit testing.
        Returns:
            list: List of yml files read from repository.
        """
        new_wd = self.repo_name.split("/")[1]

        if not repo_path:
            repo_path = self.temp_folder.name

        ymls = []

        if os.path.isdir(os.path.join(repo_path, new_wd, ".github", "workflows")):
            workflows = os.listdir(
                os.path.join(repo_path, new_wd, ".github", "workflows")
            )

            for wf in workflows:
                wf_p = os.path.join(repo_path, new_wd, ".github", "workflows", wf)
                if os.path.isfile(wf_p):
                    with open(
                        wf_p,
                        "r",
                    ) as wf_in:
                        wf_yml = wf_in.read()

                        ymls.append((wf, wf_yml))
        return ymls

    def rewrite_commit(self, repo_path=None):
        """Rewrites commit history for repo so that it auto-closes the pull
        request.

        Args:
            repo_path (str, optional): Optional path to repo, otherwise uses
            the repository associated with this class. Mostly for unit testing.
            Defaults to None.

        Returns:
            bool: True if the commit was successfully re-written.
        """

        git_rebase = "git rebase -i HEAD^"

        repo_path = repo_path if repo_path else self.temp_folder.name
        new_wd = self.repo_name.split("/")[1]

        try:

            p = subprocess.Popen(
                git_rebase.split(" "),
                cwd=os.path.join(repo_path, new_wd),
                env={
                    **os.environ,
                    **{"GIT_SEQUENCE_EDITOR": "sed -i.bak 's/pick/drop/g'"},
                },
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

        except Exception as e:
            logging.error("Exception during rebase!")
            logging.error(f"Exception details: {str(e)}")
            if self.temp_folder:
                self.temp_folder.cleanup()
            return False

        return True

    def commit_file(
        self,
        file_content: bytes,
        file_path: str,
        repo_path: str = None,
        message: str = "Test Commit",
    ):
        """Commit a file containing the provided content at the provided
        path.

        Args:
            repo_path (str, optional): Optional path to repo, otherwise uses
            the repository associated with this class. Mostly for unit testing.
            Defaults to None.

        Returns:
            str: The SHA1 hash of the HEAD revision, None if there was a
            failure.
        """
        repo_path = repo_path if repo_path else self.temp_folder.name
        new_wd = self.repo_name.split("/")[1]
        write_path = os.path.join(repo_path, new_wd, file_path)
        add_command = f"git add {file_path}"
        commit_command = "git commit -m"
        rev_parse = "git rev-parse HEAD"

        ret = None

        try:
            os.makedirs(os.path.dirname(write_path), exist_ok=True)
            with open(write_path, "wb") as outfile:
                outfile.write(file_content)

            p = subprocess.Popen(
                add_command.split(" "),
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p.wait()

            if p.returncode != 0:
                logger.error("Git add operation did not succeed!")
                raise Exception("Git add operation did not succeed!")

            cmd = commit_command.split(" ")
            cmd.append(message)
            p1 = subprocess.Popen(
                cmd,
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            p1.wait()

            if p1.returncode != 0:
                logger.error("Git commit operation did not succeed!")
                raise Exception("Git commit operation did not suceeed!")

            p2 = subprocess.Popen(
                rev_parse.split(" "),
                cwd=os.path.join(repo_path, new_wd),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            p2.wait()

            if p2.returncode != 0:
                logger.error("Git rev-parse operation did not succeed!")
                raise Exception("Git rev-parse operation did not succeed!")

            ret = p2.communicate()[0].decode().strip()
        except Exception as e:
            logging.error("Exception during git commit!")
            logging.error(f"Exception details: {str(e)}")
            if self.temp_folder:
                self.temp_folder.cleanup()

        return ret

    def push_repository(
        self, upstream_branch: str, force: bool = False, repo_path: str = None
    ):
        """Push to the remote repository.

        Args:
            upstream_branch (str): Name of upstream branch to push as.
            force (bool, optional): Whether the push should be forced. Defaults
            to False.
            repo_path (str, optional): Optional path to repo, otherwise uses
            the repository associated with this class. Mostly for unit testing.
            Defaults to None.

        Returns:
            bool: True if the push operation was successful.

        """
        rev_parse = "git rev-parse --abbrev-ref HEAD"
        repo_path = repo_path if repo_path else self.temp_folder.name

        new_wd = self.repo_name.split("/")[1]

        p = subprocess.Popen(
            rev_parse.split(" "),
            cwd=os.path.join(repo_path, new_wd),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        p.wait()

        # Need to decode and strip the newline off.
        branch_name = p.communicate()[0].decode().strip()

        push_command = f"git push --set-upstream origin {branch_name}:{upstream_branch}"
        if force:
            push_command += " -f"

        logger.info(f"Executing: {push_command}")
        p1 = subprocess.Popen(
            push_command.split(" "),
            cwd=os.path.join(repo_path, new_wd),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        p1.wait()

        if p1.returncode != 0:
            logger.error("Git push operation did not succeed!")
            return False

        return True

    def delete_branch(self, target_branch: str, repo_path: str = None):
        """Deletes a branch on the remote repository.

        Args:
            target_branch (str): Name of the branch to delete.
            repo_path (str, optional): Optional path to repo, otherwise uses
            the repository associated with this class. Mostly for unit testing.
            Defaults to None.

        Returns:
            bool: True of the branch was successfully deleted, False otherwise.
        """
        delete_command = f"git push origin --delete {target_branch} -f"
        repo_path = repo_path if repo_path else self.temp_folder.name

        new_wd = self.repo_name.split("/")[1]

        p = subprocess.Popen(
            delete_command.split(" "),
            cwd=os.path.join(repo_path, new_wd),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        p.wait()

        if p.returncode != 0:
            logger.error(
                f"Git push to delete branch {target_branch} " "did not succeed!"
            )
            return False

        return True

    def __del__(self):
        """Destructor for the object, cleans up the temporary directory."""
        if self.cloned:
            self.temp_folder.cleanup()
