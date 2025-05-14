import tempfile
import os
import subprocess
import logging
import asyncio

from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)


class Git:
    """Git handler for cloning repositories and checking workflows."""

    def __init__(
        self,
        pat: str,
        repository: str,
        work_dir: str = None,
        username="Gato-X",
        email="gato-x@pwn.com",
        proxies=None,
        github_url="github.com",
    ):
        self.pat = pat
        self.repository = repository
        self.work_dir = work_dir if work_dir else tempfile.mkdtemp()
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
            f" https://{pat}@{self.github_url}/{repository}"
        )

        if len(repository.split("/")) != 2:
            raise ValueError("Repository name but be in Org/Repo format!")

        self.config_command1 = f"git config user.name '{username}'"
        self.config_command2 = f"git config user.email '{email}'"
        self.repository = repository

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()

    async def cleanup(self):
        """Clean up temporary directory"""
        if os.path.exists(self.work_dir):
            subprocess.run(["rm", "-rf", self.work_dir], check=True)

    async def get_non_default(self) -> list:
        """Get all workflows in non-default branches using an efficient approach.
        
        Uses Git's internal object system for deduplication and avoids full checkouts.
        Only processes workflows containing 'pull_request_target'.

        Returns:
            list: List of unique Workflow objects
        """
        workflows = []
        blob_workflows = {}  # Maps blob SHA to workflow objects
        commits_branches = {}  # Maps commit SHA to branch names

        logger.info(f"Processing repository {self.repository}...")
        try:
            url = f"https://{self.pat}@github.com/{self.repository}"

            # Initialize repo with sparse checkout 
            # Credit to https://github.com/boostsecurityio/poutine/ for the implementation.
            commands = [
                ["git", "init", "--quiet"],
                ["git", "remote", "add", "origin", url],
                ["git", "config", "submodule.recurse", "false"],
                ["git", "config", "core.sparseCheckout", "true"],
                ["git", "config", "index.sparse", "true"],
                ["git", "sparse-checkout", "init", "--sparse-index", "--cone"],
                ["git", "sparse-checkout", "set", ".github/workflows"],
                ["git", "fetch", "--quiet", "--no-tags", "--depth", "1", "--filter=blob:none", "origin"],
            ]
            
            for cmd in commands:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=self.work_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
            
            # Get all remote branches with their commit SHA for deduplication
            # Similar to Go's getRemoteBranches function
            proc = await asyncio.create_subprocess_exec(
                "git", 
                "ls-remote", 
                "--heads", 
                "origin",
                cwd=self.work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            # Process each branch's commit and deduplicate by commit SHA
            for line in stdout.decode().splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                    
                commit_sha = parts[0]
                ref = parts[1]
                
                if not ref.startswith("refs/heads/"):
                    continue
                    
                branch_name = ref.replace("refs/heads/", "")
                
                if branch_name not in commits_branches:
                    commits_branches.setdefault(commit_sha, []).append(branch_name)
            
            # For each unique commit, examine workflows without checkout
            for commit_sha, branches in commits_branches.items():
                if not branches:
                    continue
                    
                branch = branches[0]  # Process one branch from each unique commit
                
                # Fetch and checkout this specific branch to match Go implementation
                checkout_commands = [
                    ["git", "fetch", "--quiet", "--no-tags", "--depth", "1", "--filter=blob:none", "origin", branch],
                    ["git", "checkout", "--quiet", "-b", f"target-{branch}", "FETCH_HEAD"],
                ]
                
                for cmd in checkout_commands:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        cwd=self.work_dir,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, stderr = await proc.communicate()
                    if stderr:
                        stderr_text = stderr.decode().strip()
                        if "already exists" in stderr_text:
                            # Skip if branch already exists, continue with next commands
                            continue
                        elif "fatal:" in stderr_text:
                            logger.warning(f"Git checkout warning: {stderr_text}")
                            # Continue anyway to try the direct commit SHA approach as fallback
                
                # List workflow files in the branch without checkout
                # Try both approaches: first with commit SHA directly
                proc = await asyncio.create_subprocess_exec(
                    "git", 
                    "ls-tree", 
                    "-r", 
                    f"origin/{branch}", 
                    "--full-tree",
                    ".github/workflows",
                    cwd=self.work_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                
                if stderr:
                    stderr_text = stderr.decode().strip()
                    logger.info(stderr_text)
                    if "Not a valid object name" in stderr_text or "did not match any file" in stderr_text:
                        continue  # Branch doesn't have .github/workflows
                
                # Process each workflow file by its blob SHA
                for line in stdout.decode().splitlines():
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                        
                    blob_sha = parts[2]
                    file_path = parts[-1]
                    
                    if not (file_path.endswith(".yml") or file_path.endswith(".yaml")):
                        continue
                    
                    # Skip if we've already processed this blob SHA
                    if blob_sha in blob_workflows:
                        continue
                    
                    # Get file contents directly using git cat-file
                    proc = await asyncio.create_subprocess_exec(
                        "git", 
                        "cat-file", 
                        "blob", 
                        blob_sha,
                        cwd=self.work_dir,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    content_stdout, _ = await proc.communicate()
                    contents = content_stdout.decode()
                    
                    # Pre-filter: Skip workflows that don't contain pull_request_target
                    if 'pull_request_target' not in contents:
                        continue
                    
                    filename = os.path.basename(file_path)
                    
                    # Store by blob SHA, so we automatically deduplicate identical content
                    blob_workflows[blob_sha] = Workflow(
                        self.repository,
                        contents,
                        filename,
                        default_branch=branch,
                    )
            
            # Convert the blob_workflows map values to a list for return
            workflows = list(blob_workflows.values())

        except subprocess.CalledProcessError as e:
            logger.warning(f"Git operation failed: {e}")
        except Exception as e:
            logger.warning(f"Error processing repository {self.repository}: {e}")
        finally:
            await self.cleanup()

        return workflows

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
