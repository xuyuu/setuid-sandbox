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
 * This sandbox could be dangerous and lower the security of the system if you
 * don't know what you're doing! Read the README file and be careful.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

#include "privdrop.h"

#define endofargs ( (optind > 1) && ( argv[optind-1] != NULL )\
                   && ( argv[optind-1][0] == '-' )\
                   && ( argv[optind-1][1] == '-' )\
                   && ( argv[optind-1][2] == '\0' ) )

#define SANDBOXUSER "suidsandbox"

/*
#define SANDBOXUID 0x70020000
#define SANDBOXGID 0x70020000
*/

/* getopt() */
extern char *optarg;
extern int optind;

void usage(char *argv0)
{
  printf("Usage: %s [-c] [-P|-p] [-u <mode>] -- [target]...\n"
         "options:\n"
         "-c\t\tDon't start chroot() helper\n"
         "-P\t\tCreate a new PID namespace or abort\n"
         "-p\t\tDon't create a new PID namespace\n"
         "-u0:\t\tDo not switch uid or gid\n"
         "-u1:\t\tSwitch gid to the one of user "SANDBOXUSER", but not the uid\n"
         "-u2:\t\tSwitch uid and gid to "SANDBOXUSER"\n"
         "-u3:\t\tGet a unique uid/gid and switch to it\n"
         "-u4:\t\tLike -u1 but accept failure as long as we have a new PID"
         " namespace (default)\n\n",
         (argv0 != NULL) ? argv0 : "sandbox") ;
}

int main(int argc, char *const argv[], char *const envp[])
{
  uid_t olduid;
  gid_t oldgid;
  struct passwd *sbxuser;
  int ch, ret = -1;
  int chroot_mode = 1;
  int no_newpid_ns = 1;
  long uid_mode = 4;
  int newpid_ns = 0;    /* -1: no, 0: best effort, 1: mandatory */
  cap_value_t cap_list[4];

  /* In theory we do not rely on euid 0 -> euid N transition magic:
   * - we drop capabilities and we become non dumpable manually 
   * - however we have not reviewed the sandbox in a capability-FS environment
   *   yet
   */
  if (geteuid()) {
    fprintf(stderr, "The sandbox is not seteuid root, aborting\n");
    return EXIT_FAILURE;
  }

  if (!getuid()) {
    fprintf(stderr, "The sandbox is not designed to be run by root, aborting\n");
    return EXIT_FAILURE;
  }

  /* capabilities we need */
  cap_list[0] = CAP_SETUID;
  cap_list[1] = CAP_SETGID;
  cap_list[2] = CAP_SYS_ADMIN;  /* for CLONE_NEWPID */
  cap_list[3] = CAP_SYS_CHROOT;

  /* Reduce capabilities to what we need. This is generally useless because:
   * 1. we will still have root euid (unless capability FS is used)
   * 2. the capabilities we keep are root equivalent
   * It's useful to drop CAP_SYS_RESSOURCE so that RLIMIT_NOFILE becomes
   * effective though
   */
  if (set_capabilities(cap_list, sizeof(cap_list)/sizeof(cap_list[0]))) {
    fprintf(stderr, "Could not adjust capabilities, aborting\n");
    return EXIT_FAILURE;
  }

  olduid = getuid();
  oldgid = getgid();

  while ((ch = getopt(argc, argv, "hcu:NPp")) != -1) {
    switch (ch) {
    case 'h':
      usage(argv[0]);
      return EXIT_SUCCESS;
    case 'c':
      chroot_mode = 0;
      break;
    case 'u':
      uid_mode = strtol(optarg, (char **) NULL, 10);
      break;
    case 'P':
      if (newpid_ns) {
        usage(argv[0]);
        return EXIT_FAILURE;
      }
      newpid_ns = 1;
      break;
    case 'p':
      if (newpid_ns) {
        usage(argv[0]);
        return EXIT_FAILURE;
      }
      newpid_ns = -1;
      break; 
    case 'N':
      fprintf(stderr, "Unsuported flag: N");
      return EXIT_FAILURE;
    default:                   /* '?' or ':' */
      usage(argv[0]);
      return EXIT_FAILURE;
    }
  }
  /* VERY IMPORTANT: CLONE_NEWPID and CLONE_FS should be in that order!
   * You can't share FS accross namespaces
   */

  /* Get a new PID namespace */
  if (newpid_ns >= 0) {
    no_newpid_ns=do_newpidns();
    if (no_newpid_ns) {
      fprintf(stderr, "Could not get new PID namespace\n");
      if (newpid_ns > 0) 
        return EXIT_FAILURE;
    }
  }

  /* launch chroot helper */
  if (chroot_mode) {
    ret = do_chroot();
    if (ret) {
      fprintf(stderr, "Could not launch chroot helper\n");
      return EXIT_FAILURE;
    }
  }

  sbxuser = getpwnam(SANDBOXUSER);

  /* change uid and / or gid */
  switch (uid_mode) {
  case 4:
    if (!sbxuser) {
      fprintf(stderr, "Could not find user %s\n", SANDBOXUSER);
      
      /* it's ok to keep uid/gid only if we have a new PID ns */
      if (no_newpid_ns) {
        ret = -1;
      } else {
        ret = do_setuid(olduid, oldgid);
      }
    } else {
      ret = do_setuid(olduid, sbxuser->pw_gid);
    }
    break;
  case 2:
    if (!sbxuser) {
      fprintf(stderr, "Could not find user %s\n", SANDBOXUSER);
      ret = -1;
    } else {
      ret = do_setuid(sbxuser->pw_uid, sbxuser->pw_gid);
    }
    break;
  case 1:
    if (!sbxuser) {
      fprintf(stderr, "Could not find user %s\n", SANDBOXUSER);
      ret = -1;
    } else {
      ret = do_setuid(olduid, sbxuser->pw_gid);
    }
    break;
  case 0:
    ret = do_setuid(olduid, oldgid);
    break;
  case 3:
  default:
    fprintf(stderr, "Unsupported uid mode (%ld)\n", uid_mode);
    return EXIT_FAILURE;
  }

  /* could not switch uid */
  if (ret) {
    fprintf(stderr, "Could not properly drop privileges\n");
    return EXIT_FAILURE;
  }

  /* sanity check
   * FIXME: add capabilities
   */
  if (geteuid() == 0 || getegid() == 0 || !setuid(0) || !setgid(0)) {
    fprintf(stderr, "My euid or egid is 0! Something went really wrong\n");
    return EXIT_FAILURE;
  }

  /* we are now unprivileged! */

  fprintf(stderr,
          "Hi from the sandbox! I'm pid=%d, uid=%d, gid=%d, dumpable=%c\n",
          getpid(), getuid(), getgid(), getdumpable()? 'Y' : 'N');

  /* Make sure we were called with "--" */
  if (endofargs && argv[optind]) {
    fprintf(stderr, "Executing %s\n", argv[optind]);

  /* Check if we will become dumpable */
  /* FIXME: abort on this ? */
    ret=open(argv[optind], O_RDONLY);
    if (ret != -1) {
      fprintf(stderr,
             "Warning: we will become dumpable after execve()!\n"
             "  please make %s non readable\n", argv[optind]);

      if (close(ret)) {
        perror("close");
        return EXIT_FAILURE;
      }
    }
 
    execvp(argv[optind], argv + optind);
    perror("exec failed");
    return EXIT_FAILURE;
  } else {
    fprintf(stderr, "Executing /bin/sh\n");
    execlp("/bin/sh", "sh", NULL);
    perror("exec failed");
    return EXIT_FAILURE;
  }

  return 0;
}
