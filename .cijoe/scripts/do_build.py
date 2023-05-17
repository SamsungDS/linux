"""
Build Linux kernel
======================

Build Linux kernel.

Retargetable: True
------------------
"""
from pathlib import Path
import logging
import os

def main(args, cijoe, step):
    """Build Linux kernel"""

    outputdir = cijoe.config.options["make"]["args"]["outputdir"]
    toolchain = cijoe.config.options["make"]["args"]["toolchain"]
    arch = cijoe.config.options["make"]["args"]["arch"]
    verbose = cijoe.config.options["make"]["args"]["verbose"]
    if verbose:
        verbose = "12"
    else:
        verbose = "0"
    nproc = os.cpu_count()

    if toolchain == "llvm":
        cla = "LLVM=1 ARCH={arch}".format(arch=arch)
    cla += " O={odir} V={verbose} -j{nproc}".format(odir=outputdir, verbose=verbose, nproc=nproc)

    commands = [
        "env | sort",
        "ccache --show-config",
        "make {}".format(cla),
    ]

    err = 0
    for cmd in commands:
        err, state = cijoe.run(cmd)
        if err:
            err = err

    return err
