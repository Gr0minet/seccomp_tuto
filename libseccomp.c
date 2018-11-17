#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <unistd.h>

int main () {
	printf("You should see this message.\n");
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL); // kill process if filter doesn't pass
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0); 
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
					 //SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_load(ctx);
	seccomp_release(ctx);
	printf("You should see this message.\n");
	/*

	fork();
	printf("But not this one.\n");
	*/

	return EXIT_SUCCESS;
}
