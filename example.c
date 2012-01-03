/* Copyright 2009 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Julien Tinnes
 *
 * Example program using the suid sandbox
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
    if (open(tests[i], O_RDONLY) >= 0)
      printf("Opening %s: success\n", tests[i]);
    else
      printf("Opening %s: %m\n", tests[i]);

  pause();
  return 0;
}
