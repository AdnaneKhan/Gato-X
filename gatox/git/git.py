import tempfile
import os
import subprocess
import logging
import hashlib
import asyncio

from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)


class Git:
    """Git handler for cloning repositories and checking workflows."""

    def __init__(self, pat: str, repository: str, work_dir: str = None):
        self.pat = pat
        self.repository = repository
        self.work_dir = work_dir if work_dir else tempfile.mkdtemp()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()

    async def cleanup(self):
        """Clean up temporary directory"""
        if os.path.exists(self.work_dir):
            subprocess.run(["rm", "-rf", self.work_dir], check=True)

    async def get_non_default(self) -> list:
        """Get all workflows in non-default branches.

        Returns:
            list: List of Workflow objects
        """
        workflows = []
        try:
            url = f"https://{self.pat}@github.com/{self.repository}"

            # Create process to clone the repo
            proc = await asyncio.create_subprocess_exec(
                "git",
                "clone",
                "--no-checkout",
                url,
                self.work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            # Get all remote branches
            proc = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                self.work_dir,
                "branch",
                "-r",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            branches = stdout.decode().splitlines()

            for branch in branches:
                branch = branch.strip()
                if branch.startswith("origin/HEAD"):
                    continue

                # Checkout branch
                proc = await asyncio.create_subprocess_exec(
                    "git",
                    "-C",
                    self.work_dir,
                    "checkout",
                    branch.replace("origin/", ""),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()

                workflow_dir = os.path.join(self.work_dir, ".github", "workflows")
                if os.path.exists(workflow_dir):
                    for filename in os.listdir(workflow_dir):
                        if filename.endswith((".yml", ".yaml")):
                            with open(os.path.join(workflow_dir, filename), "r") as f:
                                contents = f.read()
                                workflows.append(
                                    Workflow(
                                        self.repository,
                                        contents,
                                        filename,
                                        branch=branch.replace("origin/", ""),
                                    )
                                )

        except subprocess.CalledProcessError as e:
            logger.warning(f"Git operation failed: {e}")
        except Exception as e:
            logger.warning(f"Error processing repository {self.repository}: {e}")
        finally:
            await self.cleanup()

        return workflows

    async def perform_clone(self):
        """Performs the actual git clone operation.

        Returns:
            bool: True if the git clone operation was successful, False
            otherwise.
        """
        try:
            url = f"https://{self.pat}@github.com/{self.repository}"
            proc = await asyncio.create_subprocess_exec(
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                url,
                self.work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            if proc.returncode != 0:
                logger.error("Git clone operation did not succeed!")
                raise Exception("Git clone operation did not succeed!")

            proc = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                self.work_dir,
                "config",
                "user.name",
                "Gato-X",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            proc = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                self.work_dir,
                "config",
                "user.email",
                "gato-x@pwn.com",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            proc = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                self.work_dir,
                "sparse-checkout",
                "set",
                ".github",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            if proc.returncode != 0:
                logger.error("Git checkout operation did not succeed!")
                raise Exception("Git checkout operation did not succeed!")

            self.cloned = True

        except Exception as e:
            logger.error(f"Exception during git clone of {self.repository}!")
            logger.error(f"Exception details: {str(e)}")
            await self.cleanup()
            return False

        return self.cloned

    async def extract_workflow_ymls(self, repo_path: str = None):
        """Extracts and returns all github workflow .yml files located within
        the cloned repository.

        Args:
            repo_path (str, optional): Path on disk to repository to extract
            workflow yml files from. Defaults to repository associated with
            this object. Parameter intended for future uses and unit testing.
        Returns:
            list: List of yml files read from repository.
        """
        repo_path = repo_path if repo_path else self.work_dir
        ymls = []

        if os.path.isdir(os.path.join(repo_path, ".github", "workflows")):
            workflows = os.listdir(os.path.join(repo_path, ".github", "workflows"))

            for wf in workflows:
                wf_p = os.path.join(repo_path, ".github", "workflows", wf)
                if os.path.isfile(wf_p):
                    with open(wf_p, "r") as wf_in:
                        wf_yml = wf_in.read()
                        ymls.append((wf, wf_yml))
        return ymls

    async def rewrite_commit(self, repo_path=None):
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
        repo_path = repo_path if repo_path else self.work_dir

        try:
            proc = await asyncio.create_subprocess_exec(
                *git_rebase.split(" "),
                cwd=repo_path,
                env={
                    **os.environ,
                    **{"GIT_SEQUENCE_EDITOR": "sed -i.bak 's/pick/drop/g'"},
                },
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

        except Exception as e:
            logger.error("Exception during rebase!")
            logger.error(f"Exception details: {str(e)}")
            await self.cleanup()
            return False

        return True

    async def commit_file(
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
        repo_path = repo_path if repo_path else self.work_dir
        write_path = os.path.join(repo_path, file_path)
        add_command = f"git add {file_path}"
        commit_command = "git commit -m"
        rev_parse = "git rev-parse HEAD"

        ret = None

        try:
            os.makedirs(os.path.dirname(write_path), exist_ok=True)
            with open(write_path, "wb") as outfile:
                outfile.write(file_content)

            proc = await asyncio.create_subprocess_exec(
                *add_command.split(" "),
                cwd=repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            if proc.returncode != 0:
                logger.error("Git add operation did not succeed!")
                raise Exception("Git add operation did not succeed!")

            cmd = commit_command.split(" ")
            cmd.append(message)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            if proc.returncode != 0:
                logger.error("Git commit operation did not succeed!")
                raise Exception("Git commit operation did not succeed!")

            proc = await asyncio.create_subprocess_exec(
                *rev_parse.split(" "),
                cwd=repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                logger.error("Git rev-parse operation did not succeed!")
                raise Exception("Git rev-parse operation did not succeed!")

            ret = stdout.decode().strip()
        except Exception as e:
            logger.error("Exception during git commit!")
            logger.error(f"Exception details: {str(e)}")
            await self.cleanup()

        return ret

    async def push_repository(
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
        repo_path = repo_path if repo_path else self.work_dir

        proc = await asyncio.create_subprocess_exec(
            *rev_parse.split(" "),
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        # Need to decode and strip the newline off.
        branch_name = stdout.decode().strip()

        push_command = f"git push --set-upstream origin {branch_name}:{upstream_branch}"
        if force:
            push_command += " -f"

        logger.info(f"Executing: {push_command}")
        proc = await asyncio.create_subprocess_exec(
            *push_command.split(" "),
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        if proc.returncode != 0:
            logger.error("Git push operation did not succeed!")
            return False

        return True

    async def delete_branch(self, target_branch: str, repo_path: str = None):
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
        repo_path = repo_path if repo_path else self.work_dir

        proc = await asyncio.create_subprocess_exec(
            *delete_command.split(" "),
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        if proc.returncode != 0:
            logger.error(f"Git push to delete branch {target_branch} did not succeed!")
            return False

        return True
