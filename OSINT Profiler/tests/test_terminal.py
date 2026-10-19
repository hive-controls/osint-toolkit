import io
import unittest
from contextlib import contextmanager
from unittest.mock import Mock, patch
from osint_profiler import terminal, cli


@contextmanager
def keys(*values):
    stream = iter(values)
    @contextmanager
    def keyboard():
        yield lambda: next(stream)
    with patch.object(terminal, "keyboard", keyboard), patch("sys.stdout", new_callable=io.StringIO) as output:
        yield output


class Navigation(unittest.TestCase):
    def test_arrow_forward_and_numeric_selection(self):
        options = [(str(i), f"Item {i}") for i in range(1, 16)]
        with keys("DOWN", "DOWN", "UP", "RIGHT"):
            self.assertEqual(terminal.menu(options, "Pick"), "2")
        with keys("1", "2", "ENTER"):
            self.assertEqual(terminal.menu(options, "Pick"), "12")

    def test_back_restores_cursor(self):
        for key in ("LEFT", "BACK"):
            with keys(key) as output:
                with self.assertRaises(terminal.Back): terminal.menu([("1", "One")], "Pick")
                self.assertIn("\x1b[?25h", output.getvalue())

    def test_text_arrow_editing_and_back(self):
        with keys("LEFT", "BACKSPACE", "X", "END", "!", "ENTER"):
            self.assertEqual(terminal.ask("Text", "abc"), "aXc!")
        with keys("BACK"):
            with self.assertRaises(terminal.Back): terminal.ask("Text")

    def test_form_back_retains_prior_values(self):
        seen = []
        def first(values):
            seen.append(values.get("first"))
            return "value" if len(seen) == 1 else "edited"
        second = Mock(side_effect=[terminal.Back(), "done"])
        self.assertEqual(terminal.collect([("first", first), ("second", second)]), {"first": "edited", "second": "done"})
        self.assertEqual(seen, [None, "value"])

    def test_back_from_append_returns_to_append_then_case(self):
        store = Mock()
        with patch.object(cli, "menu", side_effect=["3", terminal.Back()]) as menu, patch.object(cli, "append_action", side_effect=terminal.Back()):
            with self.assertRaises(terminal.Back): cli.interactive_append(store, "demo")
        self.assertEqual(menu.call_count, 2)
        self.assertEqual(menu.call_args.args[2], "3")

    def test_cancelling_new_case_never_creates_case(self):
        store = Mock()
        with patch.object(cli, "collect", side_effect=terminal.Back()):
            with self.assertRaises(terminal.Back): cli.interactive_new(store)
        store.create_case.assert_not_called()

    def test_cancelling_scan_form_returns_to_tool_picker_without_scanning(self):
        store = Mock()
        with patch.object(cli, "choose", side_effect=["maigret", terminal.Back()]) as choose, patch.object(cli, "collect", side_effect=terminal.Back()), patch.object(cli, "Scanner") as scanner, patch.object(cli, "ensure_scan_authorization"):
            with self.assertRaises(terminal.Back): cli.interactive_scan(store, "demo")
        self.assertEqual(choose.call_count, 2)
        scanner.assert_not_called()

    def test_plain_number_fallback_and_back(self):
        @contextmanager
        def plain(): yield None
        with patch.object(terminal, "keyboard", plain), patch("builtins.input", side_effect=["2", ":back"]), patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(terminal.choose(["one", "two"], "Pick"), "two")
            with self.assertRaises(terminal.Back): terminal.ask("Text")

    def test_cancelling_import_after_preview_never_saves(self):
        store = Mock()
        store.preview_bytes.return_value = {"targets": []}
        path = __file__
        # Back from confirmation -> path -> source -> parent; no hidden-step trap.
        with patch.object(terminal, "choose", side_effect=["Enter a file path", terminal.Back()]), patch.object(cli, "ask", side_effect=[path, terminal.Back(), terminal.Back()]), patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(terminal.Back): cli.interactive_import(store, "demo")
        store.import_path.assert_not_called()


if __name__ == "__main__": unittest.main()
