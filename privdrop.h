#ifndef PRIVDROP_H
#define PRIVDROP_H

#ifndef CLONE_NEWPID
#define CLONE_NEWPID  0x20000000
#endif

int do_chroot(void);
int do_setuid(uid_t uid, gid_t gid);
int do_newpidns(void);
int getdumpable(void);
int setdumpable(void);
int set_capabilities(cap_value_t cap_list[], int ncap);

#endif
