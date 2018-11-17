# SECCOMP

## Strict mode

Seccomp strict mode was the first one to be added into the linux kernel. It only allow 4 syscalls: read(), write(), exit() and sigreturn().
All other syscalls would cause a SIGKILL.

First we will have a look at this first seccomp mode with a tiny example: 

```C
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main () {
	printf("Hello there!\n");
	printf("You should see this message.\n");

	fork();
	printf("But you should not see this one.\n");

	return EXIT_SUCCESS;
}
```

You can compile it and run it to see how it behaves before using seccomp.

Now we will set seccomp to strict mode. In order to do that, we use prctl() syscall. **We need to include** `sys/prctl.h` and `linux/seccomp.h`

Then we call prctl right before the call to fork:

```C
	// ...
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
	fork();
	// ...
```

Compile and run the code. What is happening ?

Now comment out the call to fork() and run it again. What happens ?

How do you think we could address this issue? Try it.

> **HINT:** You can use strace to have a better view of the process.

Now add a call to printf between prctl and fork:

```C
	// ...
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
	printf("Should we see this line or not?\n");
	fork();
	// ...
```

Once again, try to understand what happens.

Last question: comment out the first two calls to printf and try again.

## Filter mode

Well, being limited to only 4 syscalls is not handy. Thus, a filter mode was added in 2012. It allows the programmer to decide which syscalls he decides to forbid/allow.



## LibSeccomp
