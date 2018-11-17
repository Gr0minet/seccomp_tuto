#include <stdio.h>
#include <stdlib.h>

#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <unistd.h>
#include <sys/syscall.h>

int main () {
	//printf("Hello!\n");
	//printf("You should see this message.\n");

	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

	// printf works because it only use write syscall
	// printf("This one is ok too.\n");

	//fork();
	printf("But you should not see this one.\n");

	// exit_group syscall is used instead of exit here -> sigkill
	//exit(0);

	// this finally works, calling directly exit
	syscall(__NR_exit, 0);

	//return EXIT_SUCCESS;
}
