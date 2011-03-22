/* example program to use the suid sandbox
 * jln@google.com
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>

#include "libsandbox.h"

int getdumpable(void)
{
  int ret;

  ret = prctl(PR_GET_DUMPABLE, NULL, NULL, NULL, NULL);
  if (ret == -1) {
    perror("PR_GET_DUMPABLE");
    return -1;
  }
  return ret;
}

/*
 *
 * Helper functions for program who wants to get sandboxed will be implemented here
 *
 * - RLIMIT_NOFILE trick where two processes share the same file descriptors (CLONE_FILES),
 *   one uses RLIMIT_NOFILE to drop privileges, the other one can still open new descriptors (and/or recieve them through a UNIX socket)
 *
 * - simple chrootme function to get chrooted if one has been executed through "sandboxme"
 */

/* return -1 on failure */
int chrootme()
{

  long int fd = -1;
  char *sbxdesc;
  char msg = MSG_CHROOTME;
  ssize_t cnt;

  sbxdesc = getenv(SBX_D);
  if (sbxdesc == NULL)
    return -1;

  /* FIXME */
  fd = strtol(sbxdesc, (char **) NULL, 10);

  if (fd == -1)
    return -1;

  cnt = write(fd, &msg, 1);
  /* 1 is a handy size because it cannot be truncated */
  if (cnt != 1)
    return -1;

  cnt = read(fd, &msg, 1);
  if ((cnt == 1) && (msg == MSG_CHROOTED)) {
    return 0;
  } else {
    fprintf(stderr, "Error reading confirmation message\n");
    return -1;
  }

/* FIXME: we should also chdir() to "/", just in case (see known bugs) */

}

int main(void)
{

  char buf[1024];

  fprintf(stderr,
          "Hi from the sandbox example program! I'm pid=%d, uid=%d, gid=%d, dumpable=%c\n",
          getpid(), getuid(), getgid(), getdumpable()? 'Y' : 'N');

  printf("Now asking for chroot\n");
  if (chrootme()) {
    fprintf(stderr, "Asking for chroot failed");
    return EXIT_FAILURE;
  }
  else
    printf("Got chrooted successfully\n");

  printf("CWD = %s\n", getcwd(buf, sizeof(buf)) ? buf: "unknown");

  if (creat("test", 0000) < 0)
    printf("file creation (\"test\") failed: %m\n");
  if (creat("/test", 0000) < 0)
    printf("file creation (\"/test\") failed: %m\n");
  if (open(".", O_RDONLY) < 0)
    printf("Opening \".\" failed: %m\n");
  if (open("/", O_RDONLY) < 0)
    printf("Opening \"/\" failed: %m\n");
  if (open("/tmp", O_RDONLY) < 0)
    printf("Opening \"/tmp\" failed: %m\n");

  pause();
  return 0;

}
