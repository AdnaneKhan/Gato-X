![Supported Python versions](https://img.shields.io/badge/python-3.10+-blue.svg)


**Tool is undergoing final development and polish. The tool will be officially released on August 7th, 2024**

# Gato (Github Attack TOolkit) - Extreme Edition

## What is Gato-X?

Gato Extreme Edition is a hard fork of Gato, which was originally developed by 
@AdnaneKhan, @mas0nd, and @DS-koolaid. Gato-X is maintained 
by @AdnaneKhan and serves to automate advanced enumeration and exploitation
techniques against GitHub repositories and organizations for security research purposes.

Gato-X accompanies the **BlackHat USA 2024 talk: Self-Hosted GitHub CI/CD Runners: Continuous Integration, Continuous Destruction**
and the **DEF CON 32 talk Grand Theft Actions: Abusing Self-Hosted GitHub Runners** at scale.

Gato-X is a powerful tool and should only be used for ethical security research.

If scanning repositories, then the `search` and `enumerate` modes are 
safe to run. They will perform no mutable operations and only perform read requests.
As of writing, enumeration will not generate any audit log events.

The `attack` moodes should only be used against repositories you are authorized
to test against.


## New Features

### Automated Self-Hosted Runner Attacks

Gato-X automates the "Runner-on-Runner" (RoR) technique used extensively by Adnan Khan and
John Stawinski during their self-hosted runner bug bounty campaign. This feature replaces
the basic attack PoC functionality included in the original Gato.

Gato-X supports deploying runner-on-runner through fork pull requests and via push triggers.
The latter can be used for privilege escalation and lateral movement by jumping to new runners.

Under the hood, Gato-X will perform the following steps:

* Prepare Runner-on-Runner C2 Repository
* Prepare payload Gist files
* Deploy the RoR implantation payload.
* Confirm successful callback and runner installation.
* Provide user with an interactive webshell upon successful connection.

From the user's persective, it's simply: run command, get shell. What more could a hacker want?

### Enumeration for GitHub Actions Injection and Pwn Requests

Gato-X contains a powerful scanning engine for GitHub Actions Injection and
Pwn Request vulnerabilities. As of writing, Gato-X is one of the fastest tools
for the task. It is capable of scanning 35-40 *thousand* repositories in 1-2 hours
using a single GitHub PAT.

* Reachability Analysis
* Same and Cross-Repository Transitive Workflow Analysis
* Parsing and Simulation of "If Statements"
* Gate Check Detection (permission checks, etc.)
* Lightweight Source-Sink Analysis for Variables
* Priority Guidelines

For high priority Pwn Request or Injection reports, Gato-X has a true positive rate of
70-80 percent.

As an operator facing tool, Gato-X is tuned with a higher false positive rate than a tool
designed to generate alerts, but it provides contextual information to quickly 
determine if something is worth investigating or not.

### Other Improvements

* Improved Secrets Exfiltration.
* Enumeration of deployment environment secrets.
* Speed improvements for runlog analysis.
* General speed improvements throughout.
* Improved CLI interface and reports.
* Removed dependancy on Git.

## Quick Start

### Perform Self Hosted Runner Takeover

To perform a public repository self-hosted runner takeover attack, Gato-X requires a PAT with the following scopes:

`repo`, `workflow`, and `gist`.

This should be a PAT for an account that is a contributor to the target repository (i.e. submitted a typo fix).

```
gato-x a --runner-on-runner --target ORG/REPO --target-os [linux,osx,windows] --target-arch [arm,arm64,x64]
```

Gato-X will check if the user is a contributor to the repository, if not Gato-X will ask for confirmation. It is
very rare that maintainers select allowing workflows on pull request from all external users without approval,
but it has happened.

Next, Gato-X will automatically prepare a C2 repository and begin the operation. Gato-X will monitor each step
as the attack continues, exiting as gracefully as possible at each phase in case of a failure.

If the full chain succeeds, Gato-X will drop to an interactive prompt. This will execute shell commands on the
self-hosted runner.

If the target runner is non-ephemeral, use the `--keep-alive` flag. This will keep the workflow running. GitHub
Actions allows workflow runs on self-hosted runners to run for up to **5 days**.

#### Examples

* Deploying RoR using custom workflow via the push trigger.
* Deploying RoR using a PAT that only has the `repo` scope but can obtain execution via `workflow_dispatch` / `push` triggers.
* Leveraging a `repo` scoped token to bypass external contributor approval requirements, but leveraging Gato-X for RoR infrastructure setup.
* Using a `GITHUB_TOKEN` with `actions: write` from a Pwn Request to approve a fork PR from an external contributor.

### Search For GitHub Actions Vulnerabilities at GitHub Scale

First, create a GitHub PAT with the `repo` scope. Set that PAT to the
`GH_TOKEN` environment variable.

Next, use the search feature to retrieve a list of candidate repositories:

```
gato-x s -sg -q 'count:75000 /(issue_comment|pull_request_target|issues:)/ file:.github/workflows/ lang:yaml' -oT checks.txt
```

Finally, run Gato-X on the list of repositories:

```
gato-x e -R checks.txt -sr | tee gatox_output.txt
```

This will take some time depending on your computer and internet connection speed. Since the results are very long, use `tee` to save them to a file
for later review. Gato-X also supports JSON output, but that is intended for further machine analysis.

### Complex Attacks

These automated attacks only scratch the surface of the kinds of post-compromise attacks paths
that a red teamer may encounter within large GitHub Enterprise tenants. See the wiki for complex
cases and how Gato-X may help.

## Getting Started

### Installation

Gato supports OS X and Linux with at least **Python 3.10**.

In order to install the tool, simply clone the repository and use `pip install`. We 
recommend performing this within a virtual environment.

```
git clone https://github.com/AdnaneKhan/gato-x
cd gato-x
python3 -m venv venv
source venv/bin/activate
pip install .
```

### Usage

After installing the tool, it can be launched by running `gato-x`.

We recommend viewing the parameters for the base tool using `gato -h`, and the 
parameters for each of the tool's modules by running the following:

* `gato-x search -h`
* `gato-x enum -h`
* `gato-x attack -h`

The tool requires a GitHub classic PAT in order to function. To create one, log
in to GitHub and go to [GitHub Developer
Settings](https://github.com/settings/tokens) 
and select `Generate New Token` and then `Generate new token (classic)`.

After creating this token set the `GH_TOKEN` environment variable within your 
shell by running `export GH_TOKEN=<YOUR_CREATED_TOKEN>`. Alternatively, store 
the token within a secure password manager and enter it when the application 
prompts you.

For troubleshooting and additional details, such as installing in developer 
mode or running unit tests, please see the [wiki](https://github.com/AdnaneKhan/gato-x/wiki).

## Bugs

As an operator facing tool with rapidly developed features, Gato-X will have bugs. 
Typically, these are related to edge cases with run log formatting or YAML files.

If you believe you have identified a bug within the software, please open an 
issue containing the tool's output, along with the actions you were trying to
conduct.

If you are unsure if the behavior is a bug, use the discussions section instead!

## Contributing

Contributions are welcome! Please [review](https://github.com/AdnaneKhan/gato-x/wiki/Project-Design) 
the design methodology and coding standards before working on a new feature!

Additionally, if you are proposing significant changes to the tool, please open 
an issue [open an issue](https://github.com/AdnaneKhan/gato-x/issues/new) to 
start a conversation about the motivation for the changes.

## License

Gato-X is licensed under the [Apache License, Version 2.0](LICENSE).

```

Gato-X:

Copyright 2024, Adnan Khan

Original Gato Implementation:

Copyright 2023 Praetorian Security, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
