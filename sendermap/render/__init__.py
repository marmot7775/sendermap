"""Ways to show a SenderMap: a terminal view, Markdown to paste, HTML for the web page, JSON to
process.

The terminal, Markdown and HTML views render one View (view.py). The names below stay importable
from here: the MCP server says the claimed parts as the views do.
"""

from .view import (
    CLAIMED_PARTS,
    NETWORK_VALUE,
    RESOLVERS,
    NetworkGroup,
    View,
    claimed_parts,
    ct_lines,
    grouped_unknowns,
    resolver_words,
    view,
)

__all__ = [
    "CLAIMED_PARTS",
    "NETWORK_VALUE",
    "RESOLVERS",
    "NetworkGroup",
    "View",
    "claimed_parts",
    "ct_lines",
    "grouped_unknowns",
    "resolver_words",
    "view",
]
