"""Container policy: loud modules require the explicit --allow-loud flag."""

from colorama import Fore, Style


def update_loud_module_preference(show_prompt: bool) -> None:
    """The hardened image deliberately does not persist a loud preference."""
    del show_prompt


def check_loud_module_permission(site_name: str, target: str) -> bool:
    """Skip a loud module unless the CLI already received --allow-loud.

    The upstream caller bypasses this function when --allow-loud is present.
    Returning False here removes the interactive prompt and prevents a saved
    preference from silently enabling target-visible requests.
    """
    del target
    print(
        f"{Fore.YELLOW}[i] '{site_name}' is a loud module and was skipped "
        f"(pass --allow-loud to run it explicitly).{Style.RESET_ALL}"
    )
    return False
