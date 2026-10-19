# Repository tests

`test_public_tree.py` guards the public tree: no case data, databases, secrets or key-shaped strings may be tracked, the ignore rules must cover every sensitive path, and every relative Markdown link in the tree must resolve to a tracked path. Run it from the repo root with `python -m pytest tests` (needs `git` on PATH).
