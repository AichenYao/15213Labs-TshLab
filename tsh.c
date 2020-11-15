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
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

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

//-----------------------masks for signal blocking-------------------
sigset_t mask_all, mask_sigchld;

//-----------------------Wrapper Functions--------------------------
//this accounts for error handling as done by the textbook
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
 * @brief <What does is_builtIn do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: Cite Figure 8.24 from textbook
 * It takes in the argv, a field from the token struct after calling parseline.
 * It judges if the command is a built_in command, if so, it does the job here.
 */

int builtin_command(struct cmdline_tokens *token) {
   int is_builtIn = 0;
    if (token->builtin == BUILTIN_NONE) {
       is_builtIn = 0;
    }
    else if (token->builtin == BUILTIN_QUIT) {
        exit(0);
        is_builtIn = 1;
    }
     else if (token->builtin == BUILTIN_JOBS) {
        list_jobs(STDOUT_FILENO);
        is_builtIn = 1;
    }
    else if (token->builtin == BUILTIN_BG) {
        char** argv = token->argv;
        jid_t new_job;
        pid_t new_pid_job;
        const char *cmd_line;
        if (argv[1][0] == '&'){
            sscanf(*argv, "%d", &new_job);
            //if the job argument is a JID
            cmd_line = job_get_cmdline(new_job);
            new_pid_job = job_get_pid(new_job);
        }
        else {
            //the job argument is a PID
            sscanf(*argv, "%d", &new_pid_job);
            jid_t new_job = job_from_pid(new_pid_job);
            cmd_line = job_get_cmdline(new_job);
        }
        kill(new_pid_job,SIGCONT);
        job_state new_job_state = BG;
        cmd_line = job_get_cmdline(new_job);
        add_job(new_pid_job, new_job_state, cmd_line);
        sio_printf("[%d] (%d) /bin/ls &\n", new_job, new_pid_job);
        //need to set the state (bg), and then add to the jobs list
        is_builtIn = 1;
    }
    else if (token->builtin == BUILTIN_FG) {
        char** argv = (token)->argv;
        jid_t new_job;
        pid_t new_pid_job;
        const char *cmd_line;
        if (argv[1][0] == '&') {
            sscanf(*argv, "%d", &new_job);
            //if the job argument is a JID
            cmd_line = job_get_cmdline(new_job);
            new_pid_job = job_get_pid(new_job);
        }
        else {
            //the job argument is a PID
           sscanf(*argv, "%d", &new_pid_job);
           jid_t new_job = job_from_pid(new_pid_job);
           cmd_line = job_get_cmdline(new_job);
        }
        kill(new_pid_job,SIGCONT);
        job_state new_job_state = FG;
        cmd_line = job_get_cmdline(new_job);
        add_job(new_pid_job, new_job_state, cmd_line);
        //need to set the state (bg), and then add to the jobs list
        is_builtIn = 1;
    }
   return is_builtIn;
}


// * @brief <What does eval do?>
//  *
//  * TODO: Delete this comment and replace it with your own.
//  *
//  * NOTE: The shell is supposed to be a long-running process, so this function
//  *       (and its helpers) should avoid exiting on error.  This is not to say
//  *       they shouldn't detect and print (or otherwise handle) errors!
//  */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    int bg;
    pid_t pid;
    sigset_t prev_mask;
    // Parse command line
    parse_result = parseline(cmdline, &token);
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }
    char **argv = token.argv;
    if (argv[0] == NULL) {
        return;
    }
    int is_builtIn = builtin_command(&token);
    if (!is_builtIn) {
       //builtin commands would be handled separately
       Sigprocmask(SIG_BLOCK, &mask_sigchld, &prev_mask);
       if ((pid = fork()) == 0) {
           //child runs the newly created user job
           setpgid(0, 0);
           Sigprocmask(SIG_SETMASK, &prev_mask, NULL);
           //assign each new child process a group ID
            if (execve(argv[0], argv, environ) < 0) {
               sio_printf("%s: Command not found\n", argv[0]);
               exit(-1);
            }
        }
        //parent waits for foreground job to terminate
        //the following is for the parent only
        if (parse_result == PARSELINE_BG) {
            //if the command line ends with "bg"
            bg = 1;
        }
        Sigprocmask(SIG_BLOCK, &mask_all, NULL); //block all signals
        jid_t job = job_from_pid(pid);
        const char *cmdline = job_get_cmdline(job);
        job_state cur_state = job_get_state(job);
        if (bg) {
            //if the job is a job in the background
            add_job(pid, cur_state, cmdline);
            //print if the job is in background
            //format: [job_id] (pid) cmdline
            sio_printf("[%d] (%d) %s", job, pid, cmdline);
        }
        else {
            add_job(pid, cur_state, cmdline);
        }
        Sigprocmask(SIG_SETMASK, &prev_mask, NULL); //restore original signals
        if (!bg) {
            int status;
            if (waitpid(pid, &status, 0) < 0) {
                perror("waitfig error");
            }
        }
    }
    return;
}

/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
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

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers

    Sigfillset(&mask_all); //block SIGCHLD
    Sigemptyset(&mask_sigchld);
    Sigaddset(&mask_sigchld, SIGCHLD);
    
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    
    Signal(SIGTTIN, SIG_IGN); //ignore :background read from the terminal
    Signal(SIGTTOU, SIG_IGN); //ignore :background wrote to the terminal
    Signal(SIGQUIT, sigquit_handler);
  

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

/**
 * @brief <What does sigchld_handler do?>
 * takes in 
 * TODO: When a child terminates or stops because it received a SIGSTOP, SIGSTP,
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
    sigset_t prev_mask;
    Sigfillset(&mask_all);
    //alwways save and restore the errno flag
    while ((pid = waitpid(-1, &status, WNOHANG|WUNTRACED)) > 0){
        Sigprocmask(SIG_BLOCK, &mask_all, &prev_mask); //block signal
        //the first argument is -1 so we can reap all zombie children
        jid_t job = job_from_pid(pid);
        if (WIFSTOPPED(status)) {
            //if the child was stopped by a signal
            //delete the old job and add a new one with the state set to ST
            //job ID in [], PID in ()
            job_set_state(job, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n",
            job, pid, WSTOPSIG(status));
        }
        else if (WIFSIGNALED(status)) {
            //if the child was terminated by a signal that was not caught
            sio_printf("Job [%d] (%d) terminated by signal %d\n",
            job, pid, WTERMSIG(status));
            delete_job(job);
        }
        else{
            delete_job(job);
        }
    }
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL); //restore the blocked signal
    errno = olderrno;
    return;
}

/**
 * @brief <What does sigint_handler do?>
 * //param[in]: input signal to be sent to the foreground job
 * TODO: sigint handles Ctrl-C from the keyboard. When the shell receives this
 * signal from the kernel, the handler sends it to the foreground if there 
 * exists such one.
 */
void sigint_handler(int sig) {
    jid_t foreground_job = fg_job();
    sigset_t prev_mask;
    Sigfillset(&mask_all);
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_mask); //block signal
    int olderrno = errno;
    if (foreground_job != 0) {
        //if fg_job() returns 0, then there is no foreground job
        pid_t fg_job_pid = job_get_pid(foreground_job);
        kill(fg_job_pid, sig);
    }
    errno = olderrno;
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL); //restore the blocked signal
    return;
}

/**
 * @brief <What does sigstp_handler do?>
 * //param[in]: input signal to be sent to the foreground job
 * TODO: sigint handles Ctrl-Z from the keyboard. When the shell receives this
 * signal from the kernel, the handler sends it to the foreground if there 
 * exists such one.
 */
void sigtstp_handler(int sig) {
    jid_t foreground_job = fg_job();
    int olderrno = errno;
    sigset_t prev_mask;
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
    if (foreground_job != 0) {
        //if fg_job() returns 0, then there is no foreground job
        pid_t fg_job_pid = job_get_pid(foreground_job);
        kill(fg_job_pid, sig);
    }
    errno = olderrno;
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL);
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
