.PHONY: sync test lint smoke verify taxonomy

sync:
	uv sync

test:
	uv run pytest

lint:
	uv run ruff check .

smoke:
	uv run mcp-slayer --taxonomy
	uv run python -m mcp_slayer --taxonomy

taxonomy:
	uv run mcp-slayer --taxonomy

verify: test lint smoke
