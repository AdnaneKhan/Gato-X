![Supported Python versions](https://img.shields.io/badge/python-3.10+-blue.svg)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# Gato (Github Attack TOolkit) - Extreme Edition

Gato-X is a _FAST_ scanning and attack tool for GitHub Actions pipelines. You can use it to identify
Pwn Requests, Actions Injection, TOCTOU Vulnerabilities, and Self-Hosted Runner takeover at scale using just a single API token.

As an example, you can scan all repositories Apache's GitHub organization in minutes from a MacBook Air with a broadband internet connection.

<p align="center">
  <img src="demo.svg" width=600>
</p>

Gato-X is an operator focused tool that is tuned to avoid false negatives. It will have a higher false positive rate than SAST tools like CodeQL, but Gato-X will give you everything you need to quickly determine if something is a true positive or not!

The `search` and `enumerate` modes are safe to run on all public repositories, and
you will not violate any rules by doing so.

Gato-X's attack features should only be used with authorization, and make sure
to follow responsible disclosure if you find vulnerabilities with Gato-X.

**Gato-X is a powerful tool and should only be used for ethical security research purposes.**


## Table of Contents

- [What is Gato-X?](#what-is-gato-x)
- [New Features](#new-features)
  - [Automated Self Hosted Runner Takeover](#automated-self-hosted-runner-attacks)
  - [Enumeration for Pwn Requests and Injection](#enumeration-for-github-actions-injection-and-pwn-requests)
  - [Other Improvements](#other-improvements)
  - [Features Coming Soon](#features-coming-soon)
    - [Composite Action Analysis](#analyze-referenced-composite-actions)
    - [LLM Augmented Analysis](#llm-powered-result-analysis)
- [Hall of Fame](#hall-of-fame)
- [Quick Start](#quick-start)
  - [Perform Runner Takeover](#perform-self-hosted-runner-takeover)
  - [Scan for Vulnerabilities](#search-for-github-actions-vulnerabilities-at-github-scale)
  - [Advanced Attacks](#complex-attacks)
- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Usage](#usage)
- [Usage](#usage)
- [Bugs](#bugs)
- [Contributing](#contributing)
- [License](#license)

## What is Gato-X?

Gato Extreme Edition is a hard fork of Gato, which was originally developed by 
@AdnaneKhan, @mas0nd, and @DS-koolaid. Gato-X is maintained 
by @AdnaneKhan and serves to automate advanced enumeration and exploitation
techniques against GitHub repositories and organizations for security research purposes.

Gato-X accompanies the **BlackHat USA 2024 talk: Self-Hosted GitHub CI/CD Runners: Continuous Integration, Continuous Destruction**
and the **DEF CON 32 talk Grand Theft Actions: Abusing Self-Hosted GitHub Runners** at scale.

## New Features

### Automated Self-Hosted Runner Attacks

Gato-X automates the "Runner-on-Runner" (RoR) technique used extensively by Adnan Khan and
John Stawinski during their self-hosted runner bug bounty campaign. This feature replaces
the basic attack PoC functionality included in the original version of Gato.

Gato-X supports deploying RoR through fork pull requests. Gato-X also supports
creating a RoR payload only, which can be used in conjunction with the `push` workflow
functionality to jump to internal self-hosted runners.

Under the hood, Gato-X will perform the following steps:

* Prepare RoR C2 Repository
* Prepare payload Gist files
* Deploy the RoR implantation payload.
* Confirm successful callback and runner installation.
* Provide user with an interactive webshell upon successful connection.

From the user's persective, it's simply: run command, get shell. What more could a hacker want?

### Enumeration for GitHub Actions Injection and Pwn Requests

Gato-X contains a powerful scanning engine for GitHub Actions Injection and
Pwn Request vulnerabilities. As of writing, Gato-X is one of the fastest tools
for the task. It is capable of scanning 35-40 *thousand* repositories in 1-2 hours
using a single GitHub PAT. This is the most sophisticated new feature in Gato-X and is the result of countless hours of development and iteration in my spare time over the last six months.

* Reachability Analysis
* Same and Cross-Repository Transitive Workflow Analysis
* Parsing and Simulation of "If Statements"
* Gate Check Detection (permission checks, etc.)
* Lightweight Source-Sink Analysis for Variables
* Priority Guidelines

As an operator facing tool, Gato-X is tuned with a higher false positive rate than a tool designed to generate alerts, but it provides contextual information to quickly 
determine if something is worth investigating or not. To aid in triage, Gato-X attempts to apply confidence ratings to its reports.

### Other Improvements

* Improved Secrets Exfiltration.
* Enumeration of deployment environment secrets.
* Speed improvements for runlog analysis.
* General speed improvements throughout.
* Improved CLI interface and reports.
* Removed dependancy on Git.

### Features Coming Soon

There are a number of features I plan to add to Gato-X in the coming weeks or months.

#### Analyze Referenced Composite Actions

Currently, Gato-X does not analyze referenced composite actions. In some cases, risky operations can be performed within composite actions (such as referencing user-controlled context variables or checking out PR code).

The problem with this is that retrieving an additional file requires an addition round trip request. This can significantly slow down enumeration. This will probably be an option that is disabled by default when I add it.

#### LLM Powered Result Analysis 

Gato-X's biggest weakness is identifying injection points that
are outputs of steps that run arbitrary code. This creates a lot of 'UNKNOWN' confidence Actions Injection Reports. Using LLMs to reason about whether a variable is user control or not based on context will allow further narrowing down results. This feature will likely include support for passing an OpenAI API key and some Gato-X system prompts that I will use to inform ChatGPT of what to look for and how to respond.

Similarly, this can apply to capture code that performs permission checks or enforces immutable references.

## Hall of Fame

In order to motivate hackers to use Gato-X to find and report vulnerabilities in open-source repositories, I've
created a mini [hall of fame](https://github.com/AdnaneKhan/Gato-X/wiki/Hall-of-Fame). If you found an issue
with Gato-X and reported it, feel free to follow the instructions on the page so I can add your accomplishment
for all to see!

## Quick Start

### Perform Self Hosted Runner Takeover

To perform a public repository self-hosted runner takeover attack, Gato-X requires a PAT with the following scopes:

`repo`, `workflow`, and `gist`.

This should be a PAT for an account that is a _contributor_ to the target repository (i.e. submitted a typo fix).

```
gato-x a --runner-on-runner --target ORG/REPO --target-os [linux,osx,windows] --target-arch [arm,arm64,x64]
```
It is very rare that maintainers select allowing workflows on pull request from all external users without approval,
but it has happened.

Next, Gato-X will automatically prepare a C2 repository and begin the operation. Gato-X will monitor each step
as the attack continues, exiting as gracefully as possible at each phase in case of a failure. If workflow approval
is required, Gato-X will wait a short period of time before exiting.

If the full chain succeeds, Gato-X will drop to an interactive prompt. This will execute shell commands on the
self-hosted runner.

If the target runner is non-ephemeral, use the `--keep-alive` flag. This will keep the workflow running. GitHub
Actions allows workflow runs on self-hosted runners to run for up to **5 days** (as of writing, this might change - it was 30 days).

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

#### Examples

* Deploying RoR using custom workflow via the push trigger.
* Deploying RoR using a PAT that only has the `repo` scope but can obtain execution via `workflow_dispatch` / `push` triggers.
* Leveraging a `repo` scoped token to bypass external contributor approval requirements, but leveraging Gato-X for RoR infrastructure setup.
* Using a `GITHUB_TOKEN` with `actions: write` from a Pwn Request to approve a fork PR from an external contributor.

## Getting Started

### Installation

Gato supports OS X and Linux with at least **Python 3.10**.

Gato-X is published on PyPi, so you can simply install it with `pip install gato-x`

In order to install the tool from source, simply clone the repository and use `pip install`. 

We recommend performing this within a virtual environment.

```
git clone https://github.com/AdnaneKhan/gato-x
cd gato-x
python3 -m venv venv
source venv/bin/activate
pip install .
```
OR You can use pipx
```
git clone https://github.com/AdnaneKhan/gato-x
cd gato-x
pipx install .
```

If you need to make on-the-fly modifications, then install it in editable mode with `pip install -e`.

### Usage

After installing the tool, it can be launched by running `gato-x`.

We recommend viewing the parameters for the base tool using `gato -h`, and the 
parameters for each of the tool's modules by running the following:

* `gato-x search -h`
* `gato-x enum -h`
* `gato-x attack -h`

The tool requires a GitHub classic PAT in order to function. To create one, log
in to GitHub, go to [GitHub Developer Settings](https://github.com/settings/tokens) 
and select `Generate New Token` and then `Generate new token (classic)`.

After creating this token set the `GH_TOKEN` environment variable within your 
shell by running `export GH_TOKEN=<YOUR_CREATED_TOKEN>`. Alternatively, enter it when the application 
prompts you.

For troubleshooting and additional details, such as installing in developer 
mode or running unit tests, please see the [wiki](https://github.com/AdnaneKhan/gato-x/wiki).

## Bugs

As an operator facing tool with rapidly developed features, Gato-X will have bugs. 
Typically, these are related to edge cases with run log formatting or YAML files.

If you believe you have identified a bug within the software, please open an 
issue containing the tool's output, along with the actions you were trying to
conduct.

## Contributing

Contributions are welcome! Please [review](https://github.com/AdnaneKhan/gato-x/wiki/Project-Design) 
the design methodology before working on a new feature!

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
