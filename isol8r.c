#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <linux/limits.h>
#include <grp.h>
#include <sys/sysmacros.h>

#define A (1024*1024)
#define B "newroot"

static pid_t w = -1;

static int x(const char *y,int z,int aa,int ab) {
        FILE *ac=fopen(y,"w");
        if(!ac) {
                perror("fopen map_file");
                return -1;
        }
        if(fprintf(ac,"%d %d %d\n",z,aa,ab)<0) {
                perror("fprintf map_file");
                fclose(ac);
                return -1;
        }
        fclose(ac);
        return 0;
}

static void v() {
        for(int ad=0; ad<=CAP_LAST_CAP; ad++) {
                if(prctl(PR_CAPBSET_DROP,ad,0,0,0)==-1)perror("prctl CAPBSET_DROP");
        }
        if(prctl(PR_SET_KEEPCAPS,0,0,0,0)==-1)perror("prctl PR_SET_KEEPCAPS");
        if(setgid(1000)==-1||setuid(1000)==-1) { //gid & uid
                perror("dropping privileges");
                exit(EXIT_FAILURE);
        }
        if(setgroups(0,NULL)==-1) {
                perror("setgroups");
                exit(EXIT_FAILURE);
        }
}

static int u() {
        scmp_filter_ctx ae=seccomp_init(SCMP_ACT_KILL);
        if(!ae) {
                fprintf(stderr,"seccomp_init failed\n");
                return -1;
        }
        int af[]= {SCMP_SYS(read),SCMP_SYS(write),SCMP_SYS(exit),SCMP_SYS(exit_group),SCMP_SYS(futex),SCMP_SYS(clock_gettime),SCMP_SYS(nanosleep),SCMP_SYS(brk),SCMP_SYS(mmap),SCMP_SYS(munmap),SCMP_SYS(rt_sigreturn),SCMP_SYS(rt_sigaction),SCMP_SYS(rt_sigprocmask),SCMP_SYS(getpid),SCMP_SYS(gettid),SCMP_SYS(getcwd),SCMP_SYS(openat),SCMP_SYS(close),SCMP_SYS(access),SCMP_SYS(lseek),SCMP_SYS(fstat),SCMP_SYS(stat),SCMP_SYS(readlink),SCMP_SYS(prlimit64),SCMP_SYS(set_tid_address),SCMP_SYS(set_robust_list),SCMP_SYS(clock_gettime),SCMP_SYS(execve),SCMP_SYS(execveat),SCMP_SYS(uname),SCMP_SYS(getrandom)};
        for(size_t ag=0; ag<sizeof(af)/sizeof(af[0]); ag++) {
                if(seccomp_rule_add(ae,SCMP_ACT_ALLOW,af[ag],0)<0) {
                        fprintf(stderr,"seccomp_rule_add failed\n");
                        seccomp_release(ae);
                        return -1;
                }
        }
        if(seccomp_load(ae)<0) {
                fprintf(stderr,"seccomp_load failed\n");
                seccomp_release(ae);
                return -1;
        }
        seccomp_release(ae);
        return 0;
}

static int t(const char *ah) {
        if(mount(ah,ah,NULL,MS_BIND|MS_REC,NULL)==-1) {
                perror("mount --bind new_root");
                return -1;
        }
        char ai[PATH_MAX];
        snprintf(ai,sizeof(ai),"%s/.pivot_root",ah);
        if(mkdir(ai,0700)==-1&&errno!=EEXIST) {
                perror("mkdir .pivot_root");
                return -1;
        }
        if(syscall(SYS_pivot_root,ah,ai)==-1) {
                perror("pivot_root");
                return -1;
        }
        if(chdir("/")==-1) {
                perror("chdir /");
                return -1;
        }
        if(umount2("/.pivot_root",MNT_DETACH)==-1) {
                perror("umount old root");
                return -1;
        }
        if(rmdir("/.pivot_root")==-1) {
                perror("rmdir .pivot_root");
                return -1;
        }
        return 0;
}

static int s() {
        if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)==-1) {
                perror("mount / MS_PRIVATE");
                return -1;
        }
        if(mount("proc","/proc","proc",MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY,NULL)==-1) {
                perror("mount /proc");
                return -1;
        }
        if(mount("sysfs","/sys","sysfs",MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY,NULL)==-1) {
                perror("mount /sys");
                return -1;
        }
        if(mount("tmpfs","/dev","tmpfs",MS_NOSUID|MS_STRICTATIME,"mode=755")==-1) {
                perror("mount tmpfs /dev");
                return -1;
        }
        if(mknod("/dev/null",S_IFCHR|0666,makedev(1,3))==-1&&errno!=EEXIST)perror("mknod /dev/null");
        if(mknod("/dev/zero",S_IFCHR|0666,makedev(1,5))==-1&&errno!=EEXIST)perror("mknod /dev/zero");
        if(mknod("/dev/random",S_IFCHR|0444,makedev(1,8))==-1&&errno!=EEXIST)perror("mknod /dev/random");
        if(mknod("/dev/urandom",S_IFCHR|0444,makedev(1,9))==-1&&errno!=EEXIST)perror("mknod /dev/urandom");
        if(mount("tmpfs","/tmp","tmpfs",MS_NOSUID|MS_NODEV,"mode=1777")==-1) {
                perror("mount tmpfs /tmp");
                return -1;
        }
        return 0;
}

static void r() {
        struct rlimit aj= {1024*1024*1024,1024*1024*1024};
        if(setrlimit(RLIMIT_AS,&aj)==-1)perror("setrlimit RLIMIT_AS");
        aj.rlim_cur=aj.rlim_max=100;
        if(setrlimit(RLIMIT_NPROC,&aj)==-1)perror("setrlimit RLIMIT_NPROC");
        aj.rlim_cur=aj.rlim_max=1024;
        if(setrlimit(RLIMIT_NOFILE,&aj)==-1)perror("setrlimit RLIMIT_NOFILE");
}

static void q(int ak) {
        if(w>0)kill(w,ak);
}

static void p() {
        struct sigaction al= {0};
        al.sa_handler=q;
        sigemptyset(&al.sa_mask);
        int am[]= {SIGINT,SIGTERM,SIGHUP,SIGQUIT};
        for(size_t an=0; an<sizeof(am)/sizeof(am[0]); an++) {
                if(sigaction(am[an],&al,NULL)==-1)perror("sigaction");
        }
}

static int o(void *ao) {
        clearenv();
        if(sethostname("namespace-jail",strlen("namespace-jail"))==-1) {
                perror("sethostname");
                return 1;
        }
        if(t(B)==-1) {
                fprintf(stderr,"failed to pivot_root\n");
                return 1;
        }
        if(s()==-1) {
                fprintf(stderr,"failed to setup mounts\n");
                return 1;
        }
        r();
        // Move privilege dropping *after* mounts
        // v();
        if(u()==-1) {
                fprintf(stderr,"failed to setup seccomp\n");
                return 1;
        }
        v();
        char **ap=(char **)ao;
        if(!ap||!ap[0])ap=(char*[]) {
                "/bin/sh",NULL
        };
        execvp(ap[0],ap);
        perror("execvp");
        return 1;
}

int main(int aq,char *ar[]) {
        char *as=malloc(A);
        if(!as) {
                perror("malloc");
                exit(EXIT_FAILURE);
        }
        int at=CLONE_NEWCGROUP|CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|SIGCHLD;
#ifdef CLONE_NEWTIME
        at|=CLONE_NEWTIME;
#endif
        p();
        w=clone(o,as+A,at,ar+1);
        if(w==-1) {
                perror("clone");
                free(as);
                exit(EXIT_FAILURE);
        }
        char au[256];
        snprintf(au,sizeof(au),"/proc/%d/setgroups",w);
        FILE *av=fopen(au,"w");
        if(av) {
                fprintf(av,"deny\n");
                fclose(av);
        }
        snprintf(au,sizeof(au),"/proc/%d/uid_map",w);
        if(x(au,0,getuid(),1)==-1) {
                fprintf(stderr,"failed to write uid_map\n");
                kill(w,SIGKILL);
                free(as);
                exit(EXIT_FAILURE);
        }
        snprintf(au,sizeof(au),"/proc/%d/gid_map",w);
        if(x(au,0,getgid(),1)==-1) {
                fprintf(stderr,"failed to write gid_map\n");
                kill(w,SIGKILL);
                free(as);
                exit(EXIT_FAILURE);
        }
        int aw;
        if(waitpid(-1,&aw,0)==-1) {
                perror("waitpid");
                free(as);
                exit(EXIT_FAILURE);
        }
        free(as);
        if(WIFEXITED(aw)) {
                printf("child exited with status %d\n",WEXITSTATUS(aw));
                return WEXITSTATUS(aw);
        } else if(WIFSIGNALED(aw)) {
                printf("child killed by signal %d\n",WTERMSIG(aw));
                return 128+WTERMSIG(aw);
        } else {
                printf("child exited abnormally\n");
                return EXIT_FAILURE;
        }
}
