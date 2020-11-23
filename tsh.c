/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Aichen Yao <aicheny@andrew.cmu.edu>
 * Github ID: AichenYao
 * TODO: Include your name and Andrew ID here.
 * This program creates an interactive shell with some basic functionalities.
 * It parses single command line that the user types in to the shell and
 * performs the tasks requested. Some of the commands that my shell handles
 * include the built-ins (list-jobs, quit, etc.) and others such as echo. This
 * shell has one job running in the foreground which is always waited for to be
 * terminated while there could be multiple jobs in the background. We also
 * implement signal handlers to handle SIGCHLD, SIGTSTP, and SIGINT signals
 * separately and we apply signal blocking and unblocking when we want to run
 * some portion of the code without being interefered with other signals, often
 * in case of accessing the global variables such as the jobs list.
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);
//-----------------------Wrapper Functions--------------------------
// The wrappers are not mandatory according to the handout.
pid_t Fork(void) {
    pid_t pid;
    if ((pid = fork()) < 0) {
        perror("fork error");
    }
    return pid;
}

void Execve(const char *filename, char *const argv[], char *const envp[]) {
    if (execve(filename, argv, envp) < 0) {
        perror("execve error");
    }
    return;
}

void Sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    if (sigprocmask(how, set, oldset) < 0) {
        perror("sigprocmask error");
    }
    return;
}

void Sigemptyset(sigset_t *set) {
    if (sigemptyset(set) < 0) {
        perror("sigemptyset error");
    }
    return;
}

void Sigaddset(sigset_t *set, int signum) {
    if (sigaddset(set, signum) < 0) {
        perror("sigaddset error");
    }
    return;
}

void Sigfillset(sigset_t *set) {
    if (sigfillset(set) < 0) {
        perror("sigfillset error");
    }
    return;
}

/**
 * @brief bg_fg_job() handles the "bg job" and "fg job"  built-in commands
 *
 * @param[in]: It takes in the argv array parsed from the command line and the
 * status which shows if the job should be continued to run in the background
 * or the foreground
 *
 * NOTE: The function first extract the JID and PID from first element in argv.
 * If it starts with %, then the job argument is JID, vice versa. Then it sends
 * a SIGCONT signal to restart the process that was previously stopped. It also
 * updates its job state in the global jobs list. If the job is in foreground,
 * we wait for it to terminate using sigsuspend().
 */

void bg_fg_job(char **argv, int status) {
    sigset_t mask, prev;
    Sigemptyset(&mask);
    Sigaddset(&mask, SIGINT);
    Sigaddset(&mask, SIGTSTP);
    Sigaddset(&mask, SIGCHLD);
    // block all signals as we are accessing global variables.
    Sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t new_job = 0;
    pid_t new_pid = 0;
    const char *cmd_line;
    if (argv[1][0] == '%') {
        new_job = atoi(&argv[1][1]);
        // if the job argument is a JID
        new_pid = job_get_pid(new_job);
    } else {
        // the job argument is a PID
        new_pid = atoi(&argv[1][0]);
        new_job = job_from_pid(new_pid);
    }
    kill(-new_pid, SIGCONT);
    cmd_line = job_get_cmdline(new_job);
    // delete_job(new_job);
    // always delete the job first since we are updating its state
    if (status == BG) {
        // sio_printf("added job BG: %s \n", cmd_line);
        // add_job(new_pid, BG, cmd_line);
        job_set_state(new_job, BG);
        sio_printf("[%d] (%d) %s \n", new_job, new_pid, cmd_line);
    }
    if (status == FG) {
        job_set_state(new_job, FG);
        while (fg_job() != 0) {
            sigset_t mask_one;
            Sigemptyset(&mask_one);
            // while there is a foreground job
            sigsuspend(&mask_one);
        }
    }
    Sigprocmask(SIG_SETMASK, &prev, NULL);
    return;
}

/**
 * @brief builtin_command() judges if the command belongs to the builtins.
 *
 * @param[in]: The consequent token struct after parsing a command line
 *
 * NOTE: The function returns 1 if the command is one of these four: quit, jobs,
 * bg job, or fg job. It handls the first two in this function and calls for
 * bg_fg_job() to handle the latter two cases. Remember to pass in the right
 * status bg/fg when calling.
 */

int builtin_command(struct cmdline_tokens *token) {
    int is_builtIn = 0;
    sigset_t mask, prev;
    Sigemptyset(&mask);
    // block signals for the same reason as the function above
    Sigaddset(&mask, SIGINT);
    Sigaddset(&mask, SIGTSTP);
    Sigaddset(&mask, SIGCHLD);
    Sigprocmask(SIG_BLOCK, &mask, &prev);
    if (token->builtin == BUILTIN_NONE) {
        // not a builtin.
        is_builtIn = 0;
    } else if (token->builtin == BUILTIN_QUIT) {
        exit(0);
        is_builtIn = 1;
    } else if (token->builtin == BUILTIN_JOBS) {
        list_jobs(STDOUT_FILENO);
        is_builtIn = 1;
    } else if (token->builtin == BUILTIN_BG) {
        char **argv = token->argv;
        bg_fg_job(argv, BG);
        is_builtIn = 1;
    } else if (token->builtin == BUILTIN_FG) {
        char **argv = (token)->argv;
        bg_fg_job(argv, FG);
        is_builtIn = 1;
    }
    Sigprocmask(SIG_SETMASK, &prev, NULL);
    return is_builtIn;
}

/*
@brief eval parses a command line to the token struct containing relatble
info, such as the arguments array (argv). If the command does not contain a
builtin command (call builtin_command() to verify), then it forks a child
process and call execve() to perform what is being requested. Before calling
execve and after forking, implement redirect I/O. After calling execve(), we
update the job list with the appropriate job state.
@param[in] It takes in a command line put in by the user
*/
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    int bg = 0;
    pid_t pid;
    sigset_t mask, prev, mask_one;

    // Parse command line
    parse_result = parseline(cmdline, &token);
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        // error handling
        return;
    }
    char **argv = token.argv;
    if (argv[0] == NULL) {
        return;
    }
    int is_builtIn = builtin_command(&token);
    if (parse_result == PARSELINE_BG) {
        // if the current job runs in the background
        bg = 1;
    }
    if (!is_builtIn) {
        // builtin commands would be handled separately
        Sigemptyset(&mask_one);
        Sigemptyset(&mask);
        Sigaddset(&mask, SIGINT);
        Sigaddset(&mask, SIGTSTP);
        Sigaddset(&mask, SIGCHLD);
        Sigprocmask(SIG_BLOCK, &mask, &prev);
        if ((pid = Fork()) == 0) {
            // child runs the newly created user job
            // assign each new child process a group ID
            setpgid(0, 0);
            Sigprocmask(SIG_SETMASK, &prev, NULL);
            char *infile = token.infile;
            char *outfile = token.outfile;
            if (infile != NULL) {
                int fd1 = open(infile, O_RDWR);
                dup2(fd1, STDIN_FILENO);
                close(fd1);
            }
            if (outfile != NULL) {
                int fd2 = open(outfile, O_RDONLY);
                dup2(fd2, STDOUT_FILENO);
                close(fd2);
            }
            int exec_result = execve(argv[0], argv, environ);
            if (exec_result < 0) {
                sio_printf("%s: Command not found\n", argv[0]);
                exit(-1);
            }
        }
        // the following code is for the parent
        // block all signals when we are accessing the global variables using
        // add_job(), delete_job(), and waitpid().
        if (bg) {
            // if the job is a job in the background
            job_state cur_state = BG;
            add_job(pid, cur_state, cmdline);
            jid_t job = job_from_pid(pid);
            sio_printf("[%d] (%d) %s \n", job, pid, cmdline);
        } else {
            // if the job runs in the foreground
            job_state cur_state = FG;
            add_job(pid, cur_state, cmdline);
        }
        if (!bg) {
            while (fg_job() != 0) {
                // while there is a foreground job, wait for it to terminate
                sigsuspend(&prev);
            }
        }
    }
    Sigprocmask(SIG_SETMASK, &prev, NULL);
    return;
}

/**
 * @brief The main function gets the shell started. It first parses command line
 * and sets some starting states such as the environment variable, verbose mode,
 * install signal handlers, and initialize the job list. It also handles the
 * case when we reach the end of a line.
 * @param[in] It takes in argc, the number of arguments, and the arguments array
 * ->argv.
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)
    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers

    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z

    Signal(SIGTTIN, SIG_IGN); // ignore :background read from the terminal
    Signal(SIGTTOU, SIG_IGN); // ignore :background wrote to the terminal
    Signal(SIGQUIT, sigquit_handler);

    // Initialize the job list
    init_job_list();

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            sio_printf("%s", prompt);
            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            sio_printf("\n");
            fflush(stdout);
            fflush(stderr);
            exit(0);
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
        fflush(stdout);
    }
    return -1; // control never reaches here
}

/*****************
  Signal handlers
 *****************/

/** Handler for SIGCHLD signals
 * @brief When a child terminates or stops because it received a SIGSTOP, SIGSTP
 * SIGTTIN, or SIGTTOU signal, the kernel sends a SIGCHLD to the shell. The
 * signal handler sigchld_handler would reap all children that have just become
 * zombies.
 * Case I: If the child was stopped by a signal, set the state to ST, print out
 * the signal;
 * Case II: if the child was terminated by a signal, also print that out and
 * delete the job
 * Case III: iF the child was run to termination, just delete it
 */
void sigchld_handler(int sig) {
    int status;
    pid_t pid;
    int olderrno = errno;
    // alwways save and restore the errno flag
    sigset_t mask, prev_mask;
    Sigemptyset(&mask);
    Sigaddset(&mask, SIGCHLD);
    Sigaddset(&mask, SIGTSTP);
    Sigaddset(&mask, SIGINT);
    Sigprocmask(SIG_BLOCK, &mask, &prev_mask);
    // block all signals when accessing the job list (global)
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {
        jid_t job = job_from_pid(pid);
        if (WIFSTOPPED(status)) {
            // if the child was stopped by a signal
            // delete the old job and add a new one with the state set to ST
            // job_set_state(job, ST);
            job_set_state(job, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d \n", job, pid,
                       WSTOPSIG(status));
        } else if (WIFSIGNALED(status)) {
            // if the child was terminated by a signal that was not caught
            sio_printf("Job [%d] (%d) terminated by signal %d \n", job, pid,
                       WTERMSIG(status));
            delete_job(job);
        } else if (WIFCONTINUED(status)) {

        } else {
            // sio_printf("deleted job: %d \n", job);
            delete_job(job);
        }
    }
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL); // restore the blocked signal
    errno = olderrno;
    return;
}

/**
 * @brief handler for SIGINT signals
 * @param[in]: input signal to be sent to the foreground job
 * TODO: sigint handles Ctrl-C from the keyboard. When the shell receives this
 * signal from the kernel, the handler sends it to the foreground if there
 * exists such one.
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev_mask;
    Sigemptyset(&mask);
    Sigaddset(&mask, SIGCHLD);
    Sigaddset(&mask, SIGTSTP);
    Sigaddset(&mask, SIGINT);
    Sigprocmask(SIG_BLOCK, &mask, &prev_mask);
    // block signals
    jid_t foreground_job = fg_job();
    if (foreground_job != 0) {
        pid_t foreground_pid = job_get_pid(foreground_job);
        kill(-foreground_pid, sig);
        // pid argument here is the negative value of the pid of the fg job
        // so the signal would be sent to all processes in the same process
        // group
    }
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL); // restore the blocked signal
    errno = olderrno;
    return;
}

/**
 * @brief handler for SIGTSTP signals
 * //param[in]: input signal to be sent to the foreground job
 * TODO: sigint handles Ctrl-Z from the keyboard. When the shell receives this
 * signal from the kernel, the handler sends it to the foreground if there
 * exists such one.
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev_mask;
    Sigemptyset(&mask);
    Sigaddset(&mask, SIGCHLD);
    Sigaddset(&mask, SIGTSTP);
    Sigaddset(&mask, SIGINT);
    Sigprocmask(SIG_BLOCK, &mask, &prev_mask); // block signal
    jid_t foreground_job = fg_job();
    if (foreground_job != 0) {
        // if fg_job() returns 0, then there is no foreground job
        pid_t foreground_pid = job_get_pid(foreground_job);
        kill(-foreground_pid, sig);
    }
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
