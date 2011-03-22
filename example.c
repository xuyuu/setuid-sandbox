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

int main(void)
{

  char buf[1024];
  pid_t helper;
  int i;
  char *tests[]={".", "/", "/tmp", "0", "/0", ".."};

  fprintf(stderr,
          "Hi from the sandbox example program! I'm pid=%d, uid=%d, gid=%d, dumpable=%c\n",
          getpid(), getuid(), getgid(), getdumpable()? 'Y' : 'N');

  printf("Now asking for chroot\n");

  helper=chrootme();

  if (helper == -1) {
    fprintf(stderr, "Asking for chroot failed\n");
    return EXIT_FAILURE;
  }
  else
    printf("Got chrooted successfully. Helper (%d) RIP.\n", helper);

  printf("CWD = %s\n", getcwd(buf, sizeof(buf)) ? buf: "unknown");

  if (creat("test", 0000) < 0)
    printf("file creation (\"test\") failed: %m\n");
  if (creat("/test", 0000) < 0)
    printf("file creation (\"/test\") failed: %m\n");
  for (i = 0; i < sizeof(tests) / sizeof(tests[0]);i++)
    if (open(tests[i], O_RDONLY))
      printf("Opening %s %s\n", tests[i], open(tests[i], O_RDONLY) < 0 ? "failed" : "succeeded");

  pause();
  return 0;
}
