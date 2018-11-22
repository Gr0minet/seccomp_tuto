#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <syscall.h>

static void install_filter(void) {
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 
				 (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 (offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
	};
	struct sock_fprog prog = {
		.len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	//seccomp(SECCOMP_SET_FILTER, 0, &prog);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main () {
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

	printf("You should see this message.\n");
	install_filter();

	printf("But not this one...\n");
	exit(EXIT_SUCCESS);
}
