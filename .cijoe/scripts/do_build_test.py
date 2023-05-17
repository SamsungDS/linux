"""
collect kernel tree information
===============================

Collects a bunch of information about the kernel tree.

Retargetable: True
------------------
"""
from pathlib import Path
import logging

def main(args, cijoe, step):
    """Collect kernel tree information"""

    o = cijoe.config.options["make"]["args"]["outputdir"]
    t = cijoe.config.options["make"]["args"]["toolchain"]
    a = cijoe.config.options["make"]["args"]["arch"]
    c = cijoe.config.options["make"]["args"]["config"]
    c = " ".join(c)

    if t == "llvm":
        cla = "LLVM=1 ARCH={arch}".format(arch=a)
    cla += " O={}".format(o)
    cla += " V=12".format(o)
    cla += " {}".format(c)
    nproc = os.cpu_count()
    cla += " -j {}".format(nproc)

    commands = [
        "make help",
        "echo cla={}".format(cla),
        "echo c={}".format(c),
        "echo config={}".format(c),
        "make {}".format(cla),
    ]

    err = 0
    for cmd in commands:
        err, state = cijoe.run(cmd)
        if err:
            err = err

    return err
