"""Detonator: dynamic sandbox for Hermes plugins, MCP servers and skills."""

# Hermes imports this file as a package. pytest also imports it bare while
# collecting tests (no parent package), so only do the relative imports when
# we are actually loaded as a package.
if __package__:
    from . import commands, schemas, tools


def register(ctx):
    # The model can ask for a detonation, but only the user can approve one.
    ctx.register_tool(
        name="detonate_plugin",
        toolset="detonator",
        schema=schemas.DETONATE_PLUGIN,
        handler=tools.detonate_plugin,
    )
    # Read-only: hands a finished report to the model so it can explain it.
    # The model never decides or changes the verdict.
    ctx.register_tool(
        name="detonator_report",
        toolset="detonator",
        schema=schemas.DETONATOR_REPORT,
        handler=tools.detonator_report,
    )
    ctx.register_command(
        "detonate",
        commands.make_slash_handler(ctx),
        description="Test a plugin (catalog name or GitHub repo) in a disposable Docker sandbox (asks first)",
        args_hint="<name> | <owner/repo> [sha] [subdir] | update <name> | check",
    )
    ctx.register_cli_command(
        name="detonate",
        help="Test a plugin at an exact commit in a disposable Docker sandbox",
        setup_fn=commands.setup_cli,
        handler_fn=commands.cli_handler,
        description="Runs another plugin in a no-network Docker container with decoy secrets "
                    "and reports what it did. Asks for confirmation before running.",
    )
    ctx.register_command(
        "detonate-mcp",
        commands.make_mcp_slash_handler(ctx),
        description="Test an MCP server (a folder, or a name from your config.yaml) in a disposable "
                    "Docker sandbox (asks first)",
        args_hint="<folder> | <server-name>",
    )
    ctx.register_cli_command(
        name="detonate-mcp",
        help="Test an MCP server in a disposable Docker sandbox",
        setup_fn=commands.setup_mcp_cli,
        handler_fn=commands.mcp_cli_handler,
        description="Starts an MCP server in a no-network Docker container with decoy secrets, acts as "
                    "Hermes and calls its tools, and reports what it did. Asks for confirmation first.",
    )
    ctx.register_command(
        "detonate-skill",
        commands.make_skill_slash_handler(ctx),
        description="Test a skill (a folder, an installed skill's name, or owner/repo/folder@sha) in a "
                    "disposable Docker sandbox (asks first)",
        args_hint="<folder> | <skill-name> | <owner/repo/folder@sha>",
    )
    ctx.register_cli_command(
        name="detonate-skill",
        help="Test a skill in a disposable Docker sandbox",
        setup_fn=commands.setup_skill_cli,
        handler_fn=commands.skill_cli_handler,
        description="Reads a skill's files for planted instructions, then runs its scripts and the commands "
                    "its instructions show in a no-network Docker container with decoy secrets, and reports "
                    "what they did. Asks for confirmation first.",
    )
