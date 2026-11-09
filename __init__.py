"""Plugin Detonator: dynamic sandbox for Hermes plugins."""

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
    ctx.register_command(
        "detonate",
        commands.make_slash_handler(ctx),
        description="Test a plugin at an exact commit in a disposable Docker sandbox (asks first)",
        args_hint="<owner/repo> <sha> [subdir]",
    )
    ctx.register_cli_command(
        name="detonate",
        help="Test a plugin at an exact commit in a disposable Docker sandbox",
        setup_fn=commands.setup_cli,
        handler_fn=commands.cli_handler,
        description="Runs another plugin in a no-network Docker container with decoy secrets "
                    "and reports what it did. Asks for confirmation before running.",
    )
