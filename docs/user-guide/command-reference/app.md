# App Command

The `app` command allows security researchers to enumerate GitHub App installations using an App ID and private key. This is especially useful for incident response or security testing when a GitHub App private key has been compromised.

## Usage

```bash
gato-x app [options]
```

## Required Options

| Option | Description |
|--------|-------------|
| `--app APP_ID` | GitHub App ID |
| `--pem PATH/TO/KEY.pem` | Path to the private key file (PEM format) |

## Command Options (One Required)

You must specify one of the following:

| Option | Description |
|--------|-------------|
| `--installations` | List all installations for the GitHub App and their metadata |
| `--installation INSTALLATION_ID` | Enumerate a specific installation by ID |
| `--full` | Full enumeration of all installations accessible to the GitHub App |

## Examples

### List all installations

List all installations for the GitHub App including metadata like account name, type, and permissions:

```bash
gato-x app --installations --app 12345 --pem path/to/private-key.pem
```

### Enumerate a specific installation

Perform detailed enumeration on a specific installation:

```bash
gato-x app --installation 123456 --app 12345 --pem path/to/private-key.pem
```

### Full enumeration

Enumerate all installations accessible to the GitHub App:

```bash
gato-x app --full --app 12345 --pem path/to/private-key.pem
```

## Use Case: Grafana Incident Response

The `app` command is specifically designed to help respond to incidents like the [Grafana security incident](https://x.com/adnanthekhan/status/1916283652100559246) where App private keys may have been leaked. By using this command, security teams can quickly determine the blast radius of a leaked GitHub App private key, understanding:

1. Which organizations/accounts have installations
2. What permissions the App has
3. What repositories are accessible
4. What actions could be performed by an attacker with the private key

This allows for rapid response and mitigation in case of a GitHub App private key compromise.
