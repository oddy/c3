
# C3 password interactions with user and/or environment variables for private keys

import sys, os

from c3.constants import PASS_VAR, SHOW_VAR

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
# Policy: environment variable password must not be blank if present.

def get_env_password():
    if PASS_VAR and PASS_VAR in os.environ and os.environ[PASS_VAR]:
        return os.environ[PASS_VAR]
    return ""


def get_enter_password(prompt):
    if not sys.stdin.isatty():       # this assumes get_env_password has been called
        raise ValueError("Password can't be entered (%r environment variable can be used)" % PASS_VAR)
    else:
        return enter_password(prompt, SHOW_VAR not in os.environ)


def enter_password(prompt="Password: ", mask=True):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    pw = []
    while True:
        cc = ord(getch())
        if cc == 13:            # enter
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
            if mask:
                sys.stdout.write("*")
            else:
                sys.stdout.write(chr(cc))
            sys.stdout.flush()
            pw.append(chr(cc))

# This is used when SETTING a password.
# It fetches from env if present,
# only does a single enter if masking is OFF,
# and does the "enter twice" if masking is on.
# Note: (because this is for setting, we can have the loop in here, unlike with getting, where the
#        loop has to be synchronous with trying to decrypt the thing, so has to be in caller's code.)

def get_double_enter_setting_password(prompt1, prompt2):
    # --- Try password from environment variables ---
    passw = get_env_password()
    if passw:
        return passw

    # --- Get password from user once because showing the characters ---
    if SHOW_VAR in os.environ:        # dont do an enter-re-enter if show pass is on
        pass1 = get_enter_password(prompt1)
        return pass1
    else:
        while True:
            pass1 = get_enter_password(prompt1)
            if not pass1:
                return ""                        # user abort
            pass2 = get_enter_password(prompt2)
            if not pass2:
                return ""                        # user abort

            if pass1 == pass2:
                return pass1
            else:
                print("Sorry, entered passwords do not match, please try again")
                continue


# Testing is fairly manual, for obj reasons, something like:
# python -c "import getpassword ; print('Pass: ',getpassword.get_password('>: ', 'PASS_VAR', 'PASS_SHOW'))"

if __name__ == '__main__':
    pw = get_enter_password()
    print("Password got:  ",repr(pw))

