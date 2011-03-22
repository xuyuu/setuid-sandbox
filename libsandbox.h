#ifndef LIBSANDBOX_H
#define LIBSANDBOX_H

#define SBX_D "SBX_D"

#define MSG_CHROOTME 'C'
#define MSG_CHROOTED 'O'

int chrootme();
int getdumpable();

#endif
