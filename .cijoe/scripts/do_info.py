"""
Collect Linux kernel tree information
=====================================

Collect a bunch of information about the Linux kernel tree.

Retargetable: True
------------------
"""
from pathlib import Path
import logging

def main(args, cijoe, step):
    """Collect Linux kernel tree information."""

    commands = [
        "make kernelversion",
        "make kernelrelease",
        "git log -10 --oneline",
        "git remote -v",
        "which clang gcc aarch64-linux-gnu-gcc",
        "clang --version",
        "gcc --version",
        "aarch64-linux-gnu-gcc --version",
    ]

    err = 0
    for cmd in commands:
        err, state = cijoe.run(cmd)
        if err:
            err = err

    return err
