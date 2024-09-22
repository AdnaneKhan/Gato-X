def excluded_action(action):
    """There are some actions that we don't want to include in the graph, and the step is considered terminal."""
    if "github-script" in action:
        return True
    elif action.startswith("actions/"):
        return True
