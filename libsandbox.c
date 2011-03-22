/* bug jln@google.com
 *
 * Helper functions for program who wants to get sandboxed will be implemented here
 *
 * - RLIMIT_NOFILE trick where two processes share the same file descriptors (CLONE_FILES),
 *   one uses RLIMIT_NOFILE to drop privileges, the other one can still open new descriptors (and/or recieve them through a UNIX socket)
 *
 * - simple chrootme function to get chrooted if one has been executed through "sandboxme"
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include "libsandbox.h"

int getdumpable(void)
{
  int ret;

  ret = prctl(PR_GET_DUMPABLE, NULL, NULL, NULL, NULL);
  if (ret == -1)
    exit(EXIT_FAILURE);
  return ret;
}

/* return -1 on failure */
int chrootme()
{

  long int fd = -1;
  char *sbxdesc;
  char *helper_pid_desc;
  char msg = MSG_CHROOTME;
  ssize_t cnt;
  pid_t helper = -1, ret;

  /* Get the file descriptor of the socketpair */
  sbxdesc = getenv(SBX_D);
  if (sbxdesc == NULL)
    return -1;

  errno=0;
  fd = strtol(sbxdesc, (char **) NULL, 10);
  if (errno || (fd == -1))
    return -1;

  /* Get the PID of the setuid helper */
  helper_pid_desc = getenv(SBX_HELPER_PID);

  /* If no PID is available, the default of -1 will do */
  if (helper_pid_desc != NULL) {
    errno=0;
    helper = strtol(helper_pid_desc, (char **) NULL, 10);
    if (errno || (helper == -1))
      return -1;
  }

  cnt = write(fd, &msg, 1);
  /* 1 is a handy size because it cannot be truncated */
  if (cnt != 1)
    return -1;

  cnt = read(fd, &msg, 1);
  if ((cnt != 1) || (msg != MSG_CHROOTED)) {
    fprintf(stderr, "Error reading confirmation message\n");
    return -1;
  }

  close(fd);

  /* wait for helper process */
  ret=waitpid(helper, NULL, 0);
  if ((helper == -1) || (ret == helper))
    return 0;
  else {
    perror("waitpid");
    return -1;
  }
}
