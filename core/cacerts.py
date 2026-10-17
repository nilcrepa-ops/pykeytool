"""Locating the JDK's `cacerts` truststore (`-cacerts`).

Java does not expose a stable API for this, so the same heuristics keytool users
rely on are used: `JAVA_HOME`, then the `keytool` on PATH, then the usual
distribution locations.
"""

from __future__ import annotations

import glob
import os
import shutil

from .errors import KeytoolError


def _candidate_paths() -> list[str]:
    candidates: list[str] = []

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(os.path.join(java_home, "lib", "security", "cacerts"))
        candidates.append(os.path.join(java_home, "jre", "lib", "security", "cacerts"))

    keytool = shutil.which("keytool")
    if keytool:
        bindir = os.path.dirname(os.path.realpath(keytool))
        candidates.append(
            os.path.join(os.path.dirname(bindir), "lib", "security", "cacerts")
        )

    candidates.extend(
        [
            "/etc/ssl/certs/java/cacerts",
            "/usr/lib/jvm/default/lib/security/cacerts",
        ]
    )
    candidates.extend(sorted(glob.glob("/usr/lib/jvm/*/lib/security/cacerts")))

    return candidates


def find_cacerts() -> str:
    """Return the path of the JDK cacerts file, or raise a KeytoolError."""
    seen: set[str] = set()
    for path in _candidate_paths():
        resolved = os.path.realpath(path)
        if resolved in seen:
            continue
        seen.add(resolved)
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return path

    raise KeytoolError(
        "Could not locate the JDK 'cacerts' truststore. Set JAVA_HOME, or use "
        "-keystore with an explicit file."
    )
