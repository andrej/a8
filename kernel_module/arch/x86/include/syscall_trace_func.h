#ifndef SYSCALL_TRACE_FUNC_H
#define SYSCALL_TRACE_FUNC_H

#include <linux/ptrace.h>

struct syscall_trace_func_stack
{
// low addr, top of stack
    struct pt_regs regs;
// high addr, bottom of stack
};

/* 8n+16(%rbp)     memory argument eightbyte n     |
                             ....                  | Previous frame
      16(%rbp)     memory argument eightbyte 0     |
   ---------------------------------------------------------------------
       8(%rbp)     return address                  |
                   --------------------------------|
       0(%rbp)     previous %rbp value             |
                   --------------------------------|
      -8(%rbp)     unspecified                     | Current frame
                     ...                           |
       0(%rsp)     variable size                   |
                   (align: %rsp+8 multiple of 16)  |
		   (end of the latest allocated    |
		    stack frame)                   |
                   --------------------------------|
    -128(%rsp)     red zone                        |                          */
/*
Passing 
Once arguments are classified, the registers get assigned (in left-to-right order)
for passing as follows:
1. If the class is MEMORY, pass the argument on the stack.
2. If the class is INTEGER, the next available register of the sequence %rdi, %rsi, %rdx,
%rcx, %r8 and %r9 is used15.
3. If the class is SSE, the next available vector register is used, the registers are taken
in the order from %xmm0 to %xmm7.
*/

/*
Returning of Values
The returning of values is done according to the following algo-
rithm:
1. Classify the return type with the classification algorithm.
2. If the type has class MEMORY, then the caller provides space for the return value
and passes the address of this storage in %rdi as if it were the first argument to the
function. In effect, this address becomes a “hidden” first argument. This storage
must not overlap any data visible to the callee through other names than this argu-
ment.
On return %rax will contain the address that has been passed in by the caller in %rdi.
3. If the class is INTEGER, the next available register of the sequence %rax, %rdx is
used.
4. If the class is SSE, the next available vector register of the sequence %xmm0, %xmm1 is
used.
*/

#endif