#ifndef TRAP_INSTR_H
#define TRAP_INSTR_H

void trap_instr();
void trap_instr_end();

#define trap_instr_len (trap_instr_end - trap_instr)

#endif