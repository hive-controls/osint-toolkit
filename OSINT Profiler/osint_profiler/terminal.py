"""Small keyboard-driven menus and reversible forms; no terminal dependencies."""
from __future__ import annotations
from contextlib import contextmanager
import os
import shutil
import sys
from .util import clean


class Back(Exception):
    """Leave the current selection or return to the previous form field."""


@contextmanager
def keyboard():
    if not sys.stdin.isatty():
        raise ValueError("Interactive input requires a terminal. Use explicit command arguments instead.")
    if os.environ.get("OSINT_PLAIN_TERMINAL") == "1" or (os.name != "nt" and os.environ.get("TERM") == "dumb"):
        yield None
        return
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel.GetStdHandle.restype = wintypes.HANDLE
        kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        handle = kernel.GetStdHandle(-11 & 0xffffffff)
        mode = wintypes.DWORD()
        ansi = bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)) and kernel.SetConsoleMode(handle, mode.value | 4))
        try:
            # Some terminal wrappers forward stdout through a pipe while retaining
            # a real console input handle. Their terminal still interprets VT.
            yield read_key
        finally:
            if ansi:
                kernel.SetConsoleMode(handle, mode.value)
    elif sys.stdout.isatty() and os.environ.get("TERM") != "dumb":
        import termios
        import tty
        fd = sys.stdin.fileno()
        previous = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            yield read_key
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, previous)
    else:
        yield None


def read_key():
    if os.name == "nt":
        import msvcrt
        key = msvcrt.getwch()
        if key in ("\x00", "\xe0"):
            return {"H": "UP", "P": "DOWN", "K": "LEFT", "M": "RIGHT", "G": "HOME", "O": "END", "S": "DELETE"}.get(msvcrt.getwch(), "IGNORE")
    else:
        import select
        # Read bytes directly: buffered TextIO can hide the rest of an escape sequence.
        key = os.read(sys.stdin.fileno(), 1).decode("latin1")
        if key == "\x1b":
            sequence = ""
            while select.select([sys.stdin], [], [], .06)[0]:
                sequence += os.read(sys.stdin.fileno(), 1).decode("latin1")
                if sequence in ("[A", "[B", "[C", "[D", "[H", "[F", "OH", "OF", "[3~"):
                    break
                if len(sequence) >= 8 or (sequence and sequence[0] not in "[O"):
                    break
            return {"[A":"UP", "[B":"DOWN", "[C":"RIGHT", "[D":"LEFT", "[H":"HOME", "[F":"END", "OH":"HOME", "OF":"END", "[3~":"DELETE", "":"BACK"}.get(sequence, "IGNORE")
        first = ord(key)
        if first >= 0xc0:
            count = 2 if first < 0xe0 else 3 if first < 0xf0 else 4
            raw = bytes([first]) + os.read(sys.stdin.fileno(), count - 1)
            key = raw.decode("utf-8", errors="replace")
    if key == "\x03":
        raise KeyboardInterrupt
    if key in ("\x04", "\x1a"):
        raise Back
    return {"\r":"ENTER", "\n":"ENTER", "\x1b":"BACK", "\x08":"BACKSPACE", "\x7f":"BACKSPACE"}.get(key, key)


def line(value, width):
    return " ".join(clean(value).split())[:max(1, width - 2)]


def menu(options, title, default=None):
    """Options are (shortcut, label); numbers require Enter/Right, like line input."""
    if not options:
        raise ValueError("No items available.")
    keys = [str(key).lower() for key, _ in options]
    labels = [label for _, label in options]
    selected = keys.index(str(default).lower()) if str(default).lower() in keys else 0
    with keyboard() as read:
        if read is None:
            print("\n" + clean(title))
            for key, label in options:
                print(f"  {key}. {clean(label)}")
            while True:
                value = input("Selection (Enter highlighted default; :back returns): ").strip().lower()
                if value == ":back": raise Back
                if not value: return keys[selected]
                if value in keys: return value
                print("Choose one of the displayed shortcuts.")
        drawn = 0
        typed = ""
        def paint():
            nonlocal drawn
            width, height = shutil.get_terminal_size((80, 24))
            count = max(1, min(len(options), height - 7))
            start = max(0, min(selected - count // 2, len(options) - count))
            content = [title, "↑/↓ Move   →/Enter Select   ←/Esc Back   Number/letter + Enter"]
            for index in range(start, start + count):
                content.append(f"{'›' if index == selected else ' '} {keys[index]}. {labels[index]}")
            content.append(f"{selected+1}/{len(options)}" + (f"   Shortcut: {typed}" if typed else ""))
            if drawn: sys.stdout.write(f"\x1b[{drawn}A")
            for index in range(max(drawn, len(content))):
                value = line(content[index], width) if index < len(content) else ""
                sys.stdout.write("\r\x1b[2K" + (f"\x1b[7m{value}\x1b[0m" if index == 2 + selected - start else value) + "\n")
            if drawn > len(content): sys.stdout.write(f"\x1b[{drawn-len(content)}A")
            drawn = len(content)
            sys.stdout.flush()
        sys.stdout.write("\x1b[?25l")
        try:
            paint()
            while True:
                key = read()
                if key in ("BACK", "LEFT"): raise Back
                if key in ("UP", "DOWN", "HOME", "END"):
                    selected = (selected + (1 if key == "DOWN" else -1)) % len(options) if key in ("UP", "DOWN") else 0 if key == "HOME" else len(options)-1
                    typed = ""
                elif key in ("ENTER", "RIGHT"):
                    if not typed or typed in keys:
                        return keys[selected]
                elif key == "BACKSPACE": typed = typed[:-1]
                elif len(key) == 1 and key.isalnum():
                    candidate = typed + key.lower()
                    typed = candidate if any(k.startswith(candidate) for k in keys) else key.lower()
                if typed in keys: selected = keys.index(typed)
                paint()
        finally:
            sys.stdout.write("\x1b[0m\x1b[?25h")
            sys.stdout.flush()


def choose(items, label, display=str, default=None):
    options = [(str(i+1), display(item)) for i, item in enumerate(items)]
    initial = str(items.index(default)+1) if default in items else None
    return items[int(menu(options, label, initial))-1]


def ask(prompt, default=""):
    with keyboard() as read:
        if read is None:
            answer = input(clean(prompt) + (f" [{clean(default)}]" if default else "") + " (:back returns): ").strip()
            if answer == ":back": raise Back
            return answer or default
        print("\n" + clean(prompt) + "  [Enter continues · Esc back]")
        value = str(default)
        position = len(value)
        def paint():
            width = max(5, shutil.get_terminal_size((80, 24)).columns - 5)
            start = max(0, position - width + 1)
            shown = value[start:start+width]
            sys.stdout.write("\r\x1b[2K> " + shown + "\r\x1b[" + str(2+position-start) + "C")
            sys.stdout.flush()
        try:
            paint()
            while True:
                key = read()
                if key == "BACK": raise Back
                if key == "ENTER": return value.strip()
                if key == "LEFT": position = max(0, position-1)
                elif key == "RIGHT": position = min(len(value), position+1)
                elif key == "HOME": position = 0
                elif key == "END": position = len(value)
                elif key == "BACKSPACE" and position:
                    value = value[:position-1] + value[position:]; position -= 1
                elif key == "DELETE": value = value[:position] + value[position+1:]
                elif len(key) == 1 and key.isprintable():
                    value = value[:position] + key + value[position:]; position += 1
                paint()
        finally:
            print()


def collect(steps, initial=None):
    """A form keeps completed values while Back returns to the preceding field."""
    values = dict(initial or {})
    index = 0
    while index < len(steps):
        name, prompt = steps[index]
        try:
            values[name] = prompt(values)
            index += 1
        except Back:
            if index == 0: raise
            index -= 1
    return values


def text_field(name, label, default=""):
    return name, lambda values: ask(label, values.get(name, default))


def selection(name, label, options, default=None, display=str):
    return name, lambda values: choose(options, label, display, values.get(name, default))
