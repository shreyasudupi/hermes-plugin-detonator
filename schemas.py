"""Tool schemas for the Detonator plugin."""

DETONATE_PLUGIN = {
    "name": "detonate_plugin",
    "description": (
        "Run a third-party Hermes plugin at an exact commit inside a disposable, "
        "no-network sandbox with decoy secrets, and return an advisory report of "
        "what it actually did compared with what it declares. Requires user approval."
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
        },
        "required": ["repo", "sha"],
    },
}
