# SECCOMP

This interactive tutorial (with questions :D) is intended to show different ways to use the seccomp kernel feature. Seccomp is a security mechanism that helps programmers sandbox their own program by forbidding syscalls that can be made during execution.

We will see 3 ways to use seccomp:

 - Strict mode: the original one, not very convenient
 - Filter mode: a more flexible version, but still not very convenient
 - libseccomp: a high level API to use seccomp in a very simple way

## Strict mode

Seccomp strict mode was the first one to be added into the linux kernel. It only allows 4 syscalls: read(), write(), exit() and sigreturn().
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
	/* ... */
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
	fork();
	/* ... */
```

Compile and run the code. What is happening ?

Now comment out the call to fork() and run it again. What happens ?

How do you think we could address this issue? Try it.

> **HINT:** You can use strace to have a better view of the process.

Now add a call to printf between prctl and fork:

```C
	/* ... */
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
	printf("Should we see this line or not?\n");
	fork();
	/* ... */
```

Once again, try to understand what happens.

Last question: comment out the first two calls to printf and try again.

## Filter mode

Well, being limited to only 4 syscalls is not handy. Thus, a filter mode was added in 2012. It allows the programmer to decide which syscalls he decides to forbid/allow.

Filtering is based on BPF. It is a virtual machine that uses a very simple instruction set. Originally used for filtering network traffic, it now supports kernel syscalls filtering for seccomp.

All **instructions are same size**, and it only permits **branch-forward instructions**. It means that you can't go backward during execution (no loop).

The BPF VM uses only one register, and has read-only access to a data area that describes the system call being called (remember that the BPF program will be executed each time a system call is made).

An instruction is contained in a structure like this (see linux/filter.h):

```C
struct sock_filter {	/* Filter block */
	__u16	code;	/* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;	/* Generic multiuse field */
};
```

The first field is the opcode, written as a 16 bits number. The next two fields are 8 bits offset from current instruction location in case opcode is a jump condition. The last field is a generic one and can be used for different opcodes.

The data describing the syscall being made is expressed as a C struct like this (see linux/seccomp.h):

```C
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};
```

Where `nr` is the syscall number (architecture-dependent), `arch` is the system architecture, `instruction_pointer` is the CPU rip, and `args` are the syscall arguments.

The BFP instruction set includes:

 - Load instructions
 - Store instructions
 - Jump instructions
 - Arithmetic instructions
 - Return instructions

As the instruction set is a kind of machine code (read by BPF virtual machine), instructions are numerical. Fortunately, one can use predefined macro (see linux/bpf_common.h) to make it easier to code.

There are two types of instruction, the ones that make a jump, and the other ones.

For the first ones, we can use:

```C
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
```

And for every others:

```C
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
```

An opcode is actually constructed by ORing several values together. For instance, to load the architecture number (from seccomp_data structure) into the accumulator register, one can use :

```C
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch)))
```

With:
 - BPF_LD load
 - BPF_W is the operand size (word)
 - BPF_ABS is the source of load (data area here)

Then, we want to check if the architecture number is x86_64, and kill the process if it isn't:

```C
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch)))
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
// ...
```

These are pretty straightforward instructions : the first one does an equality check between the accumulator register (where we just loaded arch number), and the `k` field which contains x86_64 arch constant. `jt` is equal to 1, which means we will skip the next instruction in case the equality matched. In case it didn't, `jf` field equal to 0 means we will execute the next instruction, which will simply kill the process.

---

Now we know how to build instructions, let's see how to create a assemble a concrete BPF program.

In order to use seccomp with the filter mode, we need to call `prctl`:

```C
prctl(PR_SET_SECCOMP, SET_MODE_FILTER, &fprog);
```

&fprog being a pointer to a BPF program defined like this:

```C
struct sock_fprog {
	unsigned short len;	/* Number of instructions */
	struct sock_filter *filter; /* Pointer to program (array of instructions) */
};
```

/* ... */

## LibSeccomp

Writting a BPF program by hand can quickly become a tedious task. Thus, Paul Moore created a high level API to easily add seccomp filters, called libseccomp.

We will now have a look at it, and see how to simply build seccomp filters thanks to this library.

Every function of the library uses a filter context `ctx`, thus we need to create one.

```C
scmp_filter_ctx ctx;
```

We need to initialize the context with a default behaviour. The behaviour will be the one to be used in case the programm calls a syscall that does not match any of the configured seccomp filter rules (see man 3 seccomp_init).

The behaviour can be one of :

 - SCMP_ACT_KILL kill the process
 - SCMP_ACT_TRAP to send a signal to the process
 - SCMP_ACT_ERRNO to simply send a value via errno
 - SCMP_ACT_TRACE for tracing purpose
 - SCMP_ACT_ALLOW that let the process continue without effect

In most cases, we want to use SCMP_ACT_KILL to simply kill the process.

```C
ctx = seccomp_init(SCMP_ACT_KILL);
```

Now we want to add some rules to our context, otherwise our program will simply be killed at the first syscall (remember default behaviour is SCMP_ACT_KILL!).

For instance, let's say we want to allow the program to use `write()`. We use the `seccomp_rule_add` function:

```C
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
```

Now we have to load the seccomp context into the kernel. We simply use:

```C
seccomp_load(ctx);
seccomp_release(ctx);
```

`seccomp_release` let us free some memory used by the ctx struct that we don't need anymore.

You need to link your binary with `-lseccomp` to compile it.


