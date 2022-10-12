
import sys


if sys.platform == "win32":
    from msvcrt import getch  # noqa
else:
    import tty, termios
    # Note: this getch fails if not isatty on macos, and just ignores stdin on windows.
    def getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch


def get_password(prompt="P4ssword: "):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    pw = []
    while True:
        cc = ord(getch())
        if cc == 13:       # enter
            sys.stdout.write("\n")
            sys.stdout.flush()
            return "".join(pw)
        elif cc == 27:       # escape
            return ""
        elif cc == 3:        # ctrl=c
            raise KeyboardInterrupt
        elif cc in (8, 127):  # backspace, del
            if len(pw) > 0:
                sys.stdout.write("\b \b")
                sys.stdout.flush()
                pw = pw[:-1]
        elif 0 <= cc <= 31:    # unprintables
            pass
        else:               # add to password
            sys.stdout.write("*")
            sys.stdout.flush()
            pw.append(chr(cc))



if __name__ == '__main__':
    pw = get_password()
    print("Password got:  ",repr(pw))

