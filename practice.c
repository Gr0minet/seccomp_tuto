#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <unistd.h>

static void install_filter (void) {
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL); /* kill process if filter 
										  doesn't pass */
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 1,
					 SCMP_A2(SCMP_CMP_GE, 25));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
					 SCMP_A2(SCMP_CMP_GE, 10));
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
					 //SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_export_pfc(ctx, STDOUT_FILENO);
	seccomp_load(ctx);
	seccomp_release(ctx);
}

int main () {
	//printf("bonjour\n");
	install_filter();
	//fprintf(stderr, "You should this message.\n");
	fprintf(stderr, "Yaaaaaaaabbbbccccddddeeee\n");
	//fprintf(stderr, "Yaaaaaaaaaaaaaaaaaaaaaa\n");
	//printf("But not this one.\n");
	return EXIT_SUCCESS;
}
