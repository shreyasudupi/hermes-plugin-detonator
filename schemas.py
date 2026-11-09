"""Tool schemas for the Detonator plugin."""

DETONATE_PLUGIN = {
    "name": "detonate_plugin",
    "description": (
        "Prepare a Detonator run for a third-party Hermes plugin at an exact commit. "
        "Detonator runs the plugin in a disposable, no-network Docker sandbox with decoy "
        "secrets and reports what it actually did versus what it declares. This tool does "
        "not run anything: it returns the /detonate command for the user to run and approve."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "GitHub repository of the plugin, as owner/name.",
            },
            "sha": {
                "type": "string",
                "description": "Full 40-character commit SHA to test.",
            },
            "new_sha": {
                "type": "string",
                "description": "Optional newer 40-character commit SHA. When given, Detonator runs both "
                               "commits and reports what the newer version does that the older did not.",
            },
            "subdir": {
                "type": "string",
                "description": "Optional plugin folder inside the repository.",
            },
        },
        "required": ["repo", "sha"],
    },
}
