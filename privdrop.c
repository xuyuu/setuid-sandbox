/* Work in progress, Julien Tinnes <jln@google.com>
 *
 * With ideas and feedback from Tavis Ormandy and Chris Evans
 *
 * This sandbox could be dangerous and lower the security of the system if you
 * don't know what you're doing! Read the README file and be careful.
 */

#define _GNU_SOURCE
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/capability.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>

#include "privdrop.h"
#include "libsandbox.h"

#define SAFE_EMPTY_DIR "/var/sandbox-empty"

#define NTHREADS 1024

#define DESCSIZE 11
/* Create a helper process that will chroot the sandboxed process when required
 * You can request chroot() by writing a special message to the socketpair
 */
int do_chroot(void)
{

  int sv[2];
  int ret;
  ssize_t cnt;
  register pid_t pid;
  //char buf[10];
  char sdesc[DESCSIZE];
  char msg;

  ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
  if (ret == -1) {
    perror("socketpair");
    return -1;
  }

  /* FIXME: CLONE_PARENT ? */
  pid = syscall(SYS_clone, CLONE_PARENT | CLONE_FS | SIGCHLD, 0, 0, 0);

  switch (pid) {
    struct rlimit nf;

  case -1:
    perror("clone");
    return -1;

  /* child */
  case 0:
    /* We share our FS with an untrusted process
     * As a security in depth mesure, we make sure we can't open anything by mistake
     * We need to drop CAP_SYS_RESSOURCE or it's useless */
    nf.rlim_cur = 0;
    nf.rlim_max = 0;
    if (setrlimit(RLIMIT_NOFILE, &nf)) {
      perror("Helper: setrlimit");
      exit(EXIT_FAILURE);
    }

    ret = close(sv[1]);
    if (ret) {
      perror("Helper: close");
      exit(EXIT_FAILURE);
    }

    printf("Helper: write to %d ($" SBX_D") "
           "to chroot the sandboxed process\n", sv[1]);

    cnt = read(sv[0], &msg, 1);

    if (cnt == 0) {
      /* read will return 0 on EOF if sandboxed process exited */
      exit(EXIT_SUCCESS);
    } else if (cnt != 1) {
      perror("Helper: read");
      exit(EXIT_FAILURE);
    }

    if (msg != MSG_CHROOTME) {
      fprintf(stderr, "Helper: Recieved wrong message\n");
      exit(EXIT_FAILURE);
    }

    /* FIXME: change directory + check permissions first. Use /tmp and chroot
     * to /proc? */
    ret = chroot(SAFE_EMPTY_DIR);
    if (ret) {
      perror("Helper: chroot (does " SAFE_EMPTY_DIR " exist?");
      exit(EXIT_FAILURE);
    }
    ret = chdir("/");
    if (ret) {
      perror("Helper: chdir");
      exit(EXIT_FAILURE);
    }
    printf("Helper: I chrooted you\n");
    msg = MSG_CHROOTED;

    cnt = write(sv[0], &msg, 1);
    if (cnt == 1) {
      exit(EXIT_SUCCESS);
    } else {
      fprintf(stderr, "Helper: couldn't write confirmation\n");
      exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Helper: codepath error");
    exit(EXIT_FAILURE);

  default:
    /* sid=setsid();
       if (sid == -1)
       EXIT(EXIT_FAILURE)
     */
    /* FIXME */
    ret = snprintf(sdesc, sizeof(sdesc), "%u", sv[1]);
    if (ret < 0 || ret >= sizeof(sdesc)) {
      fprintf(stderr, "snprintf failed\n");
      return -1;
    }

    ret = setenv(SBX_D, sdesc, 1);
    if (ret) {
      perror("setenv");
      return -1;
    }
    ret = close(sv[0]);
    if (ret) {
      perror("close");
      return -1;
    }

    /* success */
    return 0;

  }
}

/* return -1 as a failure */
int do_setuid(uid_t uid, gid_t gid)
{

  /* We become explicitely non dumpable. Note that normally setuid() takes care
   * of this when we switch euid, but we want to support capability FS. 
   */

  if ( setdumpable() ||
      setresgid(gid, gid, gid)||
      setresuid(uid, uid, uid)) {
    return -1;
  }

  /* Drop all capabilities. Again, setuid() normally takes care of this if we had
   * euid 0
   */ 
  if (set_capabilities(NULL, 0)) {
    return -1;
  }

  return 0;
}

/* we want to unshare(), but CLONE_NEWPID is not supported in unshare
 * so we use clone() instead
 */
int do_newpidns(void)
{
  register pid_t pid;

  /* FIXME: CLONE_PARENT ? */
  pid = syscall(SYS_clone, CLONE_NEWPID | CLONE_PARENT | SIGCHLD, 0, 0, 0);

  switch (pid) {

  case -1:
    perror("clone");
    return -1;

  /* child: we are pid number 1 in the new namespace */
  case 0:
    return 0;

  default:
    exit(EXIT_SUCCESS); 
  }
}

/* this is not implemented yet (PoC code below) */
#ifdef POC_CODE_DONT_RUN

/* Try to find a suitable safe_uid.
 * We make a best effort to partition the range of safe_uids between the actual
 *   uids used on the system (likely to be successive and have different LSBs)
 * We want to avoid as much as possible a given user using the whole pool
 *   of safe_uids 
 * We return 0 as a failure, the new uid as a success.
 * Failure can mean we are in a weird state, caller should exit() after a failure
 */

uid_t do_setuid3(uid_t olduid, gid_t oldgid)
{
  struct rlimit np;
  int ret;
  uid_t sfu_start;
  uid_t sfu_end;

  /* forbid an easy DoS where one would call the sandbox to call the sandbox
   * itself */
  if (((olduid >= SAFE_UID_MIN) && (olduid <= SAFE_UID_MAX))
      || (olduid == SANDBOXUID) || (oldgid == SANDBOXGID))
    return 0;

  /* FIXME: In this PoC, we assume we have 0x10000 safe uids. */
  sfu_start = SAFE_UID_MIN + ((olduid & 0xFF) << 8);
  sfu_end = sfu_start + 0xFF;

  /* With this rlimit, setuid() will fail with EAGAIN if there is already
   * something running with this uid */
  np.rlim_cur = 1;
  np.rlim_max = NTHREADS;

  if (setrlimit(RLIMIT_NPROC, &np))
    return 0;

  do {
    ret = setgid(sfu_start);
    if (ret)
      return 0;
    ret = setuid(sfu_start);
    if (!ret) {
      /* restore rlimit and return our new uid */
      np.rlim_cur = NTHREADS;
      ret = setrlimit(RLIMIT_NPROC, &np);
      if (ret)
        return 0;
      return (sfu_start);
    }

  } while (++sfu_start <= sfu_end);

  return 0;

}
#endif

/* set capabilities in all three sets
 * we support NULL / 0 argument to drop all capabilities
 */
int set_capabilities(cap_value_t cap_list[], int ncap) {

  cap_t caps;
  int ret;

  /* caps should be initialized with all flags cleared... */
  caps=cap_init();
  if (!caps) {
    perror("cap_init");
    return -1;
  }
  /* ... but we better rely on cap_clear */
  if (cap_clear(caps)) {
    perror("cap_clear");
    return -1;
  }

  if ((cap_list) && ncap) {
    if (cap_set_flag(caps, CAP_EFFECTIVE, ncap, cap_list, CAP_SET) ||
        cap_set_flag(caps, CAP_INHERITABLE, ncap, cap_list, CAP_SET) ||
        cap_set_flag(caps, CAP_PERMITTED, ncap, cap_list, CAP_SET)) {
      perror("cap_set_flag");
      cap_free(caps);
      return -1;
    }
  }

  ret=cap_set_proc(caps);

  if (ret) {
    perror("cap_set_proc");
    cap_free(caps);
    return -1;
  }

  if (cap_free(caps)) {
    perror("cap_free");
    return -1;
  }

  return 0;
}

int getdumpable(void)
{
  int ret;

  ret = prctl(PR_GET_DUMPABLE, NULL, NULL, NULL, NULL);
  if (ret == -1) {
    perror("PR_GET_DUMPABLE");
  }
  return ret;
}

int setdumpable(void)
{
  int ret;

  ret = prctl(PR_SET_DUMPABLE, 0, NULL, NULL, NULL);
  if (ret == -1) {
    perror("PR_SET_DUMPABLE");
  }
  return ret;
}
