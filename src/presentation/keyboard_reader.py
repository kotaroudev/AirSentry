import select
import sys
import termios
import tty


class KeyboardReader:
    """
    Minimal non-blocking keyboard reader for Rich live dashboards.

    Used for MVP hotkeys:
    0 Overview
    1 WiFi Air Perimeter
    2 Bluetooth Radar
    3 Smart Packet Stream
    4 Device Intelligence
    q Quit
    """

    def __init__(self):
        self._original_settings = None

    def __enter__(self):
        self._original_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._original_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._original_settings)

    def read_key(self) -> str | None:
        if select.select([sys.stdin], [], [], 0)[0]:
            return sys.stdin.read(1)

        return None
