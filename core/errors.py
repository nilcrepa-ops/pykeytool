#!/usr/bin/env python3
"""Error types shared by the core modules and the CLI.

`KeytoolError` is the only exception the CLI is expected to surface to the user.
Anything raised as a `KeytoolError` is printed as::

    keytool error: <message>

and exits with status 1, mirroring the real `keytool`'s behaviour. Any other
exception escaping the core modules is a bug and is reported as such (see
`main.py`).
"""


class KeytoolError(Exception):
    """A user-facing error: bad input, missing file, wrong password, ..."""
