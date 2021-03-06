#pragma once

#include <stdint.h>

const uint64_t SYSCALL_READ = 0;
const uint64_t SYSCALL_WRITE = 1;
const uint64_t SYSCALL_OPEN = 2;
const uint64_t SYSCALL_CLOSE = 3;
const uint64_t SYSCALL_STAT = 4;
const uint64_t SYSCALL_FSTAT = 5;
const uint64_t SYSCALL_LSTAT = 6;
const uint64_t SYSCALL_POLL = 7;
const uint64_t SYSCALL_LSEEK = 8;
const uint64_t SYSCALL_MMAP = 9;
const uint64_t SYSCALL_MPROTECT = 10;
const uint64_t SYSCALL_MUNMAP = 11;
const uint64_t SYSCALL_BRK = 12;
const uint64_t SYSCALL_RT_SIGACTION = 13;
const uint64_t SYSCALL_RT_SIGPROCMASK = 14;
const uint64_t SYSCALL_RT_SIGRETURN = 15;
const uint64_t SYSCALL_IOCTL = 16;
const uint64_t SYSCALL_PREAD64 = 17;
const uint64_t SYSCALL_PWRITE64 = 18;
const uint64_t SYSCALL_READV = 19;
const uint64_t SYSCALL_WRITEV = 20;
const uint64_t SYSCALL_ACCESS = 21;
const uint64_t SYSCALL_PIPE = 22;
const uint64_t SYSCALL_SELECT = 23;
const uint64_t SYSCALL_SCHED_YIELD = 24;
const uint64_t SYSCALL_MREMAP = 25;
const uint64_t SYSCALL_MSYNC = 26;
const uint64_t SYSCALL_MINCORE = 27;
const uint64_t SYSCALL_MADVISE = 28;
const uint64_t SYSCALL_SHMGET = 29;
const uint64_t SYSCALL_SHMAT = 30;
const uint64_t SYSCALL_SHMCTL = 31;
const uint64_t SYSCALL_DUP = 32;
const uint64_t SYSCALL_DUP2 = 33;
const uint64_t SYSCALL_PAUSE = 34;
const uint64_t SYSCALL_NANOSLEEP = 35;
const uint64_t SYSCALL_GETITIMER = 36;
const uint64_t SYSCALL_ALARM = 37;
const uint64_t SYSCALL_SETITIMER = 38;
const uint64_t SYSCALL_GETPID = 39;
const uint64_t SYSCALL_SENDFILE = 40;
const uint64_t SYSCALL_SOCKET = 41;
const uint64_t SYSCALL_CONNECT = 41;
const uint64_t SYSCALL_ACCEPT = 43;
const uint64_t SYSCALL_SENDTO = 44;
const uint64_t SYSCALL_RECVFROM = 45;
const uint64_t SYSCALL_SENDMSG = 46;
const uint64_t SYSCALL_RECVMSG = 47;
const uint64_t SYSCALL_SHUTDOWN = 48;
const uint64_t SYSCALL_BIND = 49;
const uint64_t SYSCALL_LISTEN = 50;
const uint64_t SYSCALL_GETSOCKNAME = 51;
const uint64_t SYSCALL_GETPEERNAME = 52;
const uint64_t SYSCALL_SOCKETPAIR = 53;
const uint64_t SYSCALL_SETSOCKOPT = 54;
const uint64_t SYSCALL_GETSOCKOPT = 55;
const uint64_t SYSCALL_CLONE = 56;
const uint64_t SYSCALL_FORK = 57;
const uint64_t SYSCALL_VFORK = 58;
const uint64_t SYSCALL_EXECVE = 59;
const uint64_t SYSCALL_EXIT = 60;
const uint64_t SYSCALL_WAIT4 = 61;
const uint64_t SYSCALL_KILL = 62;
const uint64_t SYSCALL_UNAME = 63;
const uint64_t SYSCALL_SEMGET = 64;
const uint64_t SYSCALL_SEMOP = 65;
const uint64_t SYSCALL_SEMCTL = 66;
const uint64_t SYSCALL_SHMDT = 67;
const uint64_t SYSCALL_MSGGET = 68;
const uint64_t SYSCALL_MSGSND = 69;
const uint64_t SYSCALL_MSGRCV = 70;
const uint64_t SYSCALL_MSGCTL = 71;
const uint64_t SYSCALL_FCNTL = 72;
const uint64_t SYSCALL_FLOCK = 73;
const uint64_t SYSCALL_FSYNC = 74;
const uint64_t SYSCALL_FDATASYNC = 75;
const uint64_t SYSCALL_TRUNCATE = 76;
const uint64_t SYSCALL_FTRUNCATE = 77;
const uint64_t SYSCALL_GETDENTS = 78;
const uint64_t SYSCALL_GETCWD = 79;
const uint64_t SYSCALL_CHDIR = 80;
const uint64_t SYSCALL_FCHDIR = 81;
const uint64_t SYSCALL_RENAME = 82;
const uint64_t SYSCALL_MKDIR = 83;
const uint64_t SYSCALL_RMDIR = 84;
const uint64_t SYSCALL_CREAT = 85;
const uint64_t SYSCALL_LINK = 86;
const uint64_t SYSCALL_UNLINK = 87;
const uint64_t SYSCALL_SYMLINK = 88;
const uint64_t SYSCALL_READLINK = 89;
const uint64_t SYSCALL_CHMOD = 90;
const uint64_t SYSCALL_FCHMOD = 91;
const uint64_t SYSCALL_CHOWN = 92;
const uint64_t SYSCALL_FCHOWN = 93;
const uint64_t SYSCALL_LCHOWN = 94;
const uint64_t SYSCALL_UMASK = 95;
const uint64_t SYSCALL_GETTIMEOFDAY = 96;
const uint64_t SYSCALL_GETRLIMIT = 97;
const uint64_t SYSCALL_GETRUSAGE = 98;
const uint64_t SYSCALL_SYSINFO = 99;
const uint64_t SYSCALL_TIMES = 100;
const uint64_t SYSCALL_PTRACE = 101;
const uint64_t SYSCALL_GETUID = 102;
const uint64_t SYSCALL_SYSLOG = 103;
const uint64_t SYSCALL_GETGID = 104;
const uint64_t SYSCALL_SETUID = 105;
const uint64_t SYSCALL_SETGID = 106;
const uint64_t SYSCALL_GETEUID = 107;
const uint64_t SYSCALL_GETEGID = 108;
const uint64_t SYSCALL_SETPGID = 109;
const uint64_t SYSCALL_GETPPID = 110;
const uint64_t SYSCALL_GETPGRP = 111;
const uint64_t SYSCALL_SETSID = 112;
const uint64_t SYSCALL_SETREUID = 113;
const uint64_t SYSCALL_SETREGID = 114;
const uint64_t SYSCALL_GETGROUPS = 115;
const uint64_t SYSCALL_SETGROUPS = 116;
const uint64_t SYSCALL_SETRESUID = 117;
const uint64_t SYSCALL_GETRESUID = 118;
const uint64_t SYSCALL_SETRESGID = 119;
const uint64_t SYSCALL_GETRESGID = 120;
const uint64_t SYSCALL_GETPGID = 121;
const uint64_t SYSCALL_SETFSUID = 122;
const uint64_t SYSCALL_SETFSGID = 123;
const uint64_t SYSCALL_GETSID = 124;
const uint64_t SYSCALL_CAPGET = 125;
const uint64_t SYSCALL_CAPSET = 126;
const uint64_t SYSCALL_RT_SIGPENDING = 127;
const uint64_t SYSCALL_RT_SIGTIMEDWAIT = 128;
const uint64_t SYSCALL_RT_SIGQUEUEINFO = 129;
const uint64_t SYSCALL_RT_SIGSUSPEND = 130;
const uint64_t SYSCALL_SIGALTSTACK = 131;
const uint64_t SYSCALL_UTIME = 132;
const uint64_t SYSCALL_MKNOD = 133;
const uint64_t SYSCALL_USELIB = 134;
const uint64_t SYSCALL_PERSONALITY = 135;
const uint64_t SYSCALL_USTAT = 136;
const uint64_t SYSCALL_STATFS = 137;
const uint64_t SYSCALL_FSTATFS = 138;
const uint64_t SYSCALL_SYSFS = 139;
const uint64_t SYSCALL_GETPRIORITY = 140;
const uint64_t SYSCALL_SETPRIORITY = 141;
const uint64_t SYSCALL_SCHED_SETPARAM = 142;
const uint64_t SYSCALL_SCHED_GETPARAM = 143;
const uint64_t SYSCALL_SCHED_SETSCHEDULER = 144;
const uint64_t SYSCALL_SCHED_GETSCHEDULER = 145;
const uint64_t SYSCALL_SCHED_GET_PRIORITY_MAX = 146;
const uint64_t SYSCALL_SCHED_GET_PRIORITY_MIN = 147;
const uint64_t SYSCALL_SCHED_RR_GET_INTERVAL = 148;
const uint64_t SYSCALL_MLOCK = 149;
const uint64_t SYSCALL_MUNLOCK = 150;
const uint64_t SYSCALL_MLOCKALL = 151;
const uint64_t SYSCALL_MUNLOCKALL = 152;
const uint64_t SYSCALL_VHANGUP = 153;
const uint64_t SYSCALL_MODIFY_LDT = 154;
const uint64_t SYSCALL_PIVOT_ROOT = 155;
const uint64_t SYSCALL_SYSCTL = 156;
const uint64_t SYSCALL_PRCTL = 157;
const uint64_t SYSCALL_ARCH_PRCTL = 158;
const uint64_t SYSCALL_ADJTIMEX = 159;
const uint64_t SYSCALL_SETRLIMIT = 160;
const uint64_t SYSCALL_CHROOT = 161;
const uint64_t SYSCALL_SYNC = 162;
const uint64_t SYSCALL_ACCT = 163;
const uint64_t SYSCALL_SETTIMEOFDAY = 164;
const uint64_t SYSCALL_MOUNT = 165;
const uint64_t SYSCALL_UMOUNT2 = 166;
const uint64_t SYSCALL_SWAPON = 167;
const uint64_t SYSCALL_SWAPOFF = 168;
const uint64_t SYSCALL_REBOOT = 169;
const uint64_t SYSCALL_SETHOSTNAME = 170;
const uint64_t SYSCALL_SETDOMAINNAME = 171;
const uint64_t SYSCALL_IOPL = 172;
const uint64_t SYSCALL_IOPERM = 173;
const uint64_t SYSCALL_CREATE_MODULE = 174;
const uint64_t SYSCALL_INIT_MODULE = 175;
const uint64_t SYSCALL_DELETE_MODULE = 176;
const uint64_t SYSCALL_GET_KERNEL_SYMS = 177;
const uint64_t SYSCALL_QUERY_MODULE = 178;
const uint64_t SYSCALL_QUOTACTL = 179;
const uint64_t SYSCALL_NFSSERVCTL = 180;
const uint64_t SYSCALL_GETPMSG = 181;
const uint64_t SYSCALL_PUTPMSG = 182;
const uint64_t SYSCALL_AFS_SYSCALL = 183;
const uint64_t SYSCALL_TUXCALL = 184;
const uint64_t SYSCALL_SECURITY = 185;
const uint64_t SYSCALL_GETTID = 186;
const uint64_t SYSCALL_READAHEAD = 187;
const uint64_t SYSCALL_SETXATTR = 188;
const uint64_t SYSCALL_LSETXATTR = 189;
const uint64_t SYSCALL_FSETXATTR = 190;
const uint64_t SYSCALL_GETXATTR = 191;
const uint64_t SYSCALL_LGETXATTR = 192;
const uint64_t SYSCALL_FGETXATTR = 193;
const uint64_t SYSCALL_LISTXATTR = 194;
const uint64_t SYSCALL_LLISTXATTR = 195;
const uint64_t SYSCALL_FLISTXATTR = 196;
const uint64_t SYSCALL_REMOVEXATTR = 197;
const uint64_t SYSCALL_LREMOVEXATTR = 198;
const uint64_t SYSCALL_FREMOVEXATTR = 199;
const uint64_t SYSCALL_TKILL = 200;
const uint64_t SYSCALL_TIME = 201;
const uint64_t SYSCALL_FUTEX = 202;
const uint64_t SYSCALL_SCHED_SETAFFINITY = 203;
const uint64_t SYSCALL_SCHED_GETAFFINITY = 204;
const uint64_t SYSCALL_SET_THREAD_AREA = 205;
const uint64_t SYSCALL_IO_SETUP = 206;
const uint64_t SYSCALL_IO_DESTROY = 207;
const uint64_t SYSCALL_IO_GETEVENTS = 208;
const uint64_t SYSCALL_IO_SUBMIT = 209;
const uint64_t SYSCALL_IO_CANCEL = 210;
const uint64_t SYSCALL_GET_THREAD_AREA = 211;
const uint64_t SYSCALL_LOOKUP_DCOOKIE = 212;
const uint64_t SYSCALL_EPOLL_CREATE = 213;
const uint64_t SYSCALL_EPOLL_CTL_OLD = 214;
const uint64_t SYSCALL_EPOLL_WAIT_OLD = 215;
const uint64_t SYSCALL_REMAP_FILE_PAGES = 216;
const uint64_t SYSCALL_GETDENTS64 = 217;
const uint64_t SYSCALL_SET_TID_ADDRESS = 218;
const uint64_t SYSCALL_RESTART_SYSCALL = 219;
const uint64_t SYSCALL_SEMTIMEDOP = 220;
const uint64_t SYSCALL_FADVISE64 = 221;
const uint64_t SYSCALL_TIMER_CREATE = 222;
const uint64_t SYSCALL_TIMER_SETTIME = 223;
const uint64_t SYSCALL_TIMER_GETTIME = 224;
const uint64_t SYSCALL_TIMER_GETOVERRUN = 225;
const uint64_t SYSCALL_TIMER_DELETE = 226;
const uint64_t SYSCALL_CLOCK_SETTIME = 227;
const uint64_t SYSCALL_CLOCK_GETTIME = 228;
const uint64_t SYSCALL_CLOCK_GETRES = 229;
const uint64_t SYSCALL_CLOCK_NANOSLEEP = 230;
const uint64_t SYSCALL_EXIT_GROUP = 231;
const uint64_t SYSCALL_EPOLL_WAIT = 232;
const uint64_t SYSCALL_EPOLL_CTL = 233;
const uint64_t SYSCALL_TGKILL = 234;
const uint64_t SYSCALL_UTIMES = 235;
const uint64_t SYSCALL_VSERVER = 236;
const uint64_t SYSCALL_MBIND = 237;
const uint64_t SYSCALL_SET_MEMPOLICY = 238;
const uint64_t SYSCALL_GET_MEMPOLICY = 239;
const uint64_t SYSCALL_MQ_OPEN = 240;
const uint64_t SYSCALL_MQ_UNLINK = 241;
const uint64_t SYSCALL_MQ_TIMEDSEND = 242;
const uint64_t SYSCALL_MQ_TIMEDRECEIVE = 243;
const uint64_t SYSCALL_MQ_NOTIFY = 244;
const uint64_t SYSCALL_MQ_GETSETATTR = 245;
const uint64_t SYSCALL_KEXEC_LOAD = 246;
const uint64_t SYSCALL_WAITID = 247;
const uint64_t SYSCALL_ADD_KEY = 248;
const uint64_t SYSCALL_REQUEST_KEY = 249;
const uint64_t SYSCALL_KEYCTL = 250;
const uint64_t SYSCALL_IOPRIO_SET = 251;
const uint64_t SYSCALL_IOPRIO_GET = 252;
const uint64_t SYSCALL_INOTIFY_INIT = 253;
const uint64_t SYSCALL_INOTIFY_ADD_WATCH = 254;
const uint64_t SYSCALL_INOTIFY_RM_WATCH = 255;
const uint64_t SYSCALL_MIGRATE_PAGES = 256;
const uint64_t SYSCALL_OPENAT = 257;
const uint64_t SYSCALL_MKDIRAT = 258;
const uint64_t SYSCALL_MKNODAT = 259;
const uint64_t SYSCALL_FCHOWNAT = 260;
const uint64_t SYSCALL_FUTIMESAT = 261;
const uint64_t SYSCALL_NEWFSTATAT = 262;
const uint64_t SYSCALL_UNLINKAT = 263;
const uint64_t SYSCALL_RENAMEAT = 264;
const uint64_t SYSCALL_LINKAT = 265;
const uint64_t SYSCALL_SYMLINKAT = 266;
const uint64_t SYSCALL_READLINKAT = 267;
const uint64_t SYSCALL_FCHMODAT = 268;
const uint64_t SYSCALL_FACCESSAT = 269;
const uint64_t SYSCALL_PSELECT6 = 270;
const uint64_t SYSCALL_PPOLL = 271;
const uint64_t SYSCALL_UNSHARE = 272;
const uint64_t SYSCALL_SET_ROBUST_LIST = 273;
const uint64_t SYSCALL_GET_ROBUST_LIST = 274;
const uint64_t SYSCALL_SPLICE = 275;
const uint64_t SYSCALL_TEE = 276;
const uint64_t SYSCALL_SYNC_FILE_RANGE = 277;
const uint64_t SYSCALL_VMSPLICE = 278;
const uint64_t SYSCALL_MOVE_PAGES = 279;
const uint64_t SYSCALL_UTIMENSAT = 280;
const uint64_t SYSCALL_EPOLL_PWAIT = 281;
const uint64_t SYSCALL_SIGNALFD = 282;
const uint64_t SYSCALL_TIMERFD_CREATE = 283;
const uint64_t SYSCALL_EVENTFD = 284;
const uint64_t SYSCALL_FALLOCATE = 285;
const uint64_t SYSCALL_TIMERFD_SETTIME = 286;
const uint64_t SYSCALL_TIMERFD_GETTIME = 287;
const uint64_t SYSCALL_ACCEPT4 = 288;
const uint64_t SYSCALL_SIGNALFD4 = 289;
const uint64_t SYSCALL_EVENTFD2 = 290;
const uint64_t SYSCALL_EPOLL_CREATE1 = 291;
const uint64_t SYSCALL_DUP3 = 292;
const uint64_t SYSCALL_PIPE2 = 293;
const uint64_t SYSCALL_INOTIFY_INIT1 = 294;
const uint64_t SYSCALL_PREADV = 295;
const uint64_t SYSCALL_PWRITEV = 296;
const uint64_t SYSCALL_RT_TGSIGQUEUEINFO = 297;
const uint64_t SYSCALL_PERF_EVENT_OPEN = 298;
const uint64_t SYSCALL_RECVMMSG = 299;
const uint64_t SYSCALL_FANOTIFY_INIT = 300;
const uint64_t SYSCALL_FANOTIFY_MARK = 301;
const uint64_t SYSCALL_PRLIMIT64 = 302;
const uint64_t SYSCALL_NAME_TO_HANDLE_AT = 303;
const uint64_t SYSCALL_OPEN_BY_HANDLE_AT = 304;
const uint64_t SYSCALL_CLOCK_ADJTIME = 305;
const uint64_t SYSCALL_SYNCFS = 306;
const uint64_t SYSCALL_SENDMMSG = 307;
const uint64_t SYSCALL_SETNS = 308;
const uint64_t SYSCALL_GETCPU = 309;
const uint64_t SYSCALL_PROCESS_VM_READV = 310;
const uint64_t SYSCALL_PROCESS_VM_WRITEV = 311;
const uint64_t SYSCALL_KCMP = 312;
const uint64_t SYSCALL_FINIT_MODULE = 313;
const uint64_t SYSCALL_SCHED_SETATTR = 314;
const uint64_t SYSCALL_SCHED_GETATTR = 315;
const uint64_t SYSCALL_RENAMEAT2 = 316;
const uint64_t SYSCALL_SECCOMP = 317;
const uint64_t SYSCALL_GETRANDOM = 318;
const uint64_t SYSCALL_MEMFD_CREATE = 319;
const uint64_t SYSCALL_KEXEC_FILE_LOAD = 320;
const uint64_t SYSCALL_BPF = 321;
const uint64_t SYSCALL_EXECVEAT = 322;
