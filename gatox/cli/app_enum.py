from gatox.cli.output import Output
from gatox.github.app_enum import GitHubAppEnumerator

def _print_app_installations(installations):
    print("Installations:")
    for inst in installations:
        print(f"- ID: {inst['id']}, Account: {inst['account']['login']}, Permissions: {inst['permissions']}, Repos count: {inst['repository_selection']}")

async def app_enum(args, parser):
    Output.info("Starting GitHub App enumeration...")
    enumerator = GitHubAppEnumerator(args.app, args.pem, getattr(args, 'api_url', 'https://api.github.com'))
    if args.installations:
        installations = await enumerator.get_installations()
        _print_app_installations(installations)
    elif args.full:
        installations = await enumerator.get_installations()
        for inst in installations:
            print(f"\n[Installation {inst['id']}] {inst['account']['login']}")
            token = await enumerator.get_installation_token(inst['id'])
            repos = await enumerator.get_installation_repos(token)
            print(f"Repos: {[repo['full_name'] for repo in repos]}")
            print(f"Permissions: {inst['permissions']}")
    elif args.installation:
        token = await enumerator.get_installation_token(args.installation)
        repos = await enumerator.get_installation_repos(token)
        print(f"Repos: {[repo['full_name'] for repo in repos]}")
        # Permissions can be fetched from installations endpoint if needed
    else:
        parser.error("You must specify one of --installations, --full, or --installation.")
