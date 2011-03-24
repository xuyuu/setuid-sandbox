#ifndef LIBSANDBOX_H
#define LIBSANDBOX_H

#define SBX_D "SBX_D"
#define SBX_HELPER_PID "SBX_HELPER_PID"

#define MSG_CHROOTME 'C'
#define MSG_CHROOTED 'O'

pid_t chrootme();
int getdumpable();

#endif
