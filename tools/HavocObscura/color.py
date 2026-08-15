"""
Color utilities for terminal output.
Provides cross-platform colored text using colorama.
"""

from typing import Optional

from colorama import Fore, Style, init

# Initialize colorama for cross-platform compatibility
# autoreset=True automatically resets colors after each print
init(autoreset=True)


def cyan(text: str) -> str:
    """Return text in cyan color."""
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}"


def yellow(text: str) -> str:
    """Return text in yellow color."""
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"


def green(text: str) -> str:
    """Return text in green color."""
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"


def red(text: str) -> str:
    """Return text in red color."""
    return f"{Fore.RED}{text}{Style.RESET_ALL}"


def blue(text: str) -> str:
    """Return text in blue color."""
    return f"{Fore.BLUE}{text}{Style.RESET_ALL}"


def magenta(text: str) -> str:
    """Return text in magenta color."""
    return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"


def white(text: str) -> str:
    """Return text in white color."""
    return f"{Fore.WHITE}{text}{Style.RESET_ALL}"


def reset(text: str) -> str:
    """Return text with reset styling."""
    return f"{Style.RESET_ALL}{text}{Style.RESET_ALL}"


def bold(text: str) -> str:
    """Return text in bold."""
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"


def dim(text: str) -> str:
    """Return text in dim style."""
    return f"{Style.DIM}{text}{Style.RESET_ALL}"


# Semantic color aliases for common use cases
def success(text: str) -> str:
    """Return success message (green)."""
    return green(text)


def warning(text: str) -> str:
    """Return warning message (yellow)."""
    return yellow(text)


def error(text: str) -> str:
    """Return error message (red)."""
    return red(text)


def info(text: str) -> str:
    """Return info message (cyan)."""
    return cyan(text)
