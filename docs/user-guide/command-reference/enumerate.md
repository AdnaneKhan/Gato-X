# Enumerate Command

The enumerate command analyzes GitHub repositories for exploitable vulnerabilities in GitHub Actions workflows. It performs static analysis of workflow files and can analyze workflow run logs to identify self-hosted runners.

## Basic Usage

```bash
gato-x enumerate [options]
# or
gato-x enum [options]
# or
gato-x e [options]
```

## Options

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Target an organization to enumerate for self-hosted runners |
| `--repository`, `-r` | Target a single repository in org/repo format |
| `--repositories`, `-R` | A text file containing repositories in org/repo format |
| `--self-enumeration`, `-s` | Enumerate the configured token's access and all repositories or organizations the user has write access to |
| `--validate`, `-v` | Validate if the token is valid and print organization memberships |
| `--output-yaml`, `-o` | Directory to save gathered workflow yml files to |
| `--skip-runners`, `-sr` | Do NOT enumerate runners via run-log analysis |
| `--machine` | Run with a GitHub App token for single repository enumeration |
| `--ignore-workflow-run` | Ignore the `workflow_run` trigger when enumerating repositories |
| `--output-json`, `-oJ` | Save enumeration output to JSON file |
| `--deep-dive`, `-dd` | Perform deep dive static analysis, including analyzing non-default branches |
| `--cache-restore-file` | Path to JSON file containing saved reusable action files |
| `--cache-save-file` | Path to JSON file to save cache to after executing |

## Examples

### Enumerate a single repository

```bash
gato-x enumerate -r MyOrg/MyRepo
```

### Enumerate multiple repositories from a file

```bash
gato-x e -R repositories.txt
```

### Self-enumeration to identify accessible resources

```bash
gato-x e -s
```

### Validate a GitHub token

```bash
gato-x e -v
```

### Enumerate an organization with deep dive analysis

```bash
gato-x e -t MyOrganization -dd
```

### Save results to JSON for further analysis

```bash
gato-x e -R repositories.txt -oJ results.json
```

## Understanding the Output

The enumerate command performs several types of analysis:

1. **Reachability Analysis** - Determines if user-controlled inputs can reach sensitive parts of workflows
2. **Cross-Repository Analysis** - Analyzes workflows and reusable actions across repositories
3. **If Statement Simulation** - Parses and simulates conditional statements in workflows
4. **Gate Check Detection** - Identifies permission checks and other security controls
5. **Source-Sink Analysis** - Tracks variables from user inputs to sensitive operations

Results are presented with confidence ratings to help prioritize findings.
