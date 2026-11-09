"""Plugin Detonator: dynamic sandbox for Hermes plugins."""

# Hermes imports this file as a package. pytest also imports it bare while
# collecting tests (no parent package), so only do the relative import when
# we are actually loaded as a package.
if __package__:
    from . import schemas, tools


def register(ctx):
    ctx.register_tool(
        name="detonate_plugin",
        toolset="detonator",
        schema=schemas.DETONATE_PLUGIN,
        handler=tools.detonate_plugin,
    )
