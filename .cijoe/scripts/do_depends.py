"""
Install Linux kernel build dependencies
=======================================

Installs Linux kernel build time dependencies.

Retargetable: True
------------------
"""
from pathlib import Path
import logging

def main(args, cijoe, step):
    """Install Linux build dependencies."""

    pkgs = cijoe.config.options["linux"]["deps"]["packages"]
    pkgs = " ".join(pkgs)

    commands = [
        "sudo apt update -y",
        "sudo apt install {} -y".format(pkgs),
    ]

    err = 0
    for cmd in commands:
        err, state = cijoe.run(cmd)
        if err:
            err = err

    return err
