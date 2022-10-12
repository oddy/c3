
import sys, os
import six


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


# Policy: we're not supporting stdin-redirect for entering passwords.
#         it's environment variable or interactive entry only.

# returns password & flag for whether password was input interactively.

def get_password(prompt, env_var="", show_pass_var=""):
    interactive = False
    if env_var and env_var in os.environ:
        return os.environ[env_var], False
    elif not sys.stdin.isatty():
        raise ValueError("Private key password can't be entered and %r env var not set" % env_var)
    else:
        return enter_password(prompt, show_pass_var in os.environ), True


def enter_password(prompt="P4ssword: ", mask=True):
    if not mask:
        return six.moves.input(prompt)
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

