"""Disable in-container mutation; rebuild the pinned image to update."""

from importlib.metadata import PackageNotFoundError, version


def get_version(package_name: str) -> str:
    try:
        return version(package_name)
    except PackageNotFoundError:
        return "Unknown"


def update_self() -> None:
    raise RuntimeError("Self-update is disabled in the hardened container; rebuild the image")
