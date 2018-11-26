#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/syscall.h>

char username[30];

static void install_filter (void) {
    scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL); 

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
					 SCMP_A2(SCMP_CMP_LE, 1024)); 

    seccomp_load(ctx);
    seccomp_release(ctx);
}

int main (int argc, char *argv[]) {

	//install_filter();

    printf("Who said never use gets??\n");
	printf("Username: %d\n", username);
    //fgets(username, 30, stdin);
	
	syscall(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));

	username[strcspn(username, "\n")] = 0;

    printf("I guess it's not you, %s...\n", username);

    //system("/bin/echo Look, I can even put system in the plt with no worries!");

    return EXIT_SUCCESS;
}
