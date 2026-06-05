// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal libbpf loader for the per-disk block-layer error-injection demo.
 *
 * Usage: blk_error_inject_loader <block-device>
 *
 * It opens the skeleton, writes the target disk's dev_t into the struct_ops
 * map value, loads and attaches the struct_ops link (which performs the
 * in-kernel reg() of "blk_error_inject_ops"), then waits until interrupted.
 * Detaching on exit unregisters the program and drops the static-key gate.
 *
 * The disk must already be armed for error injection (BD_MAKE_IT_FAIL), e.g.
 *	echo 1 > /sys/block/<disk>/make-it-fail
 * otherwise submit_bio_noacct_nocheck() never reaches the injection path.
 */
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "blk_error_inject.skel.h"

/* Kernel dev_t encoding (MINORBITS == 20); st_rdev uses glibc's own scheme. */
#define KERNEL_MKDEV(maj, min)	(((__u32)(maj) << 20) | ((__u32)(min) & 0xfffff))

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
			   va_list args)
{
	return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
	struct blk_error_inject_bpf *skel;
	struct bpf_link *link;
	struct stat st;
	int err;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <block-device>\n", argv[0]);
		return 1;
	}
	if (stat(argv[1], &st) || !S_ISBLK(st.st_mode)) {
		fprintf(stderr, "%s is not a block device\n", argv[1]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = blk_error_inject_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	/* Select the target disk before the struct_ops map value is loaded. */
	skel->struct_ops.blk_error_inject->dev =
		KERNEL_MKDEV(major(st.st_rdev), minor(st.st_rdev));

	err = blk_error_inject_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	link = bpf_map__attach_struct_ops(skel->maps.blk_error_inject);
	if (!link) {
		fprintf(stderr, "failed to attach struct_ops (is %s armed via make-it-fail?)\n",
			argv[1]);
		err = 1;
		goto cleanup;
	}

	printf("attached to %s (%u:%u); failing WRITEs in sectors [0, 2048).\n",
	       argv[1], major(st.st_rdev), minor(st.st_rdev));
	printf("Press Ctrl-C to detach.\n");

	while (!exiting)
		sleep(1);

	bpf_link__destroy(link);
	err = 0;
cleanup:
	blk_error_inject_bpf__destroy(skel);
	return err;
}
