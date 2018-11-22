#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <unistd.h>

static void install_filter (void) {
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL); /* kill process if filter 
										  doesn't pass */
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
					 SCMP_A0(SCMP_CMP_EQ, STDERR_FILENO));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
	seccomp_load(ctx);
	seccomp_release(ctx);
}

int main () {
	install_filter();
	fprintf(stderr, "You should this message.\n");
	printf("But not this one.\n");
	//printf("You should see this message.\n");
	/*

	fork();
	printf("But not this one.\n");

	int count = 10000000;

	for (int i = 0; i < count; i++)
		getppid();
	*/
	return EXIT_SUCCESS;
}
