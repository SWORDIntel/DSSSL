/* SSH Access with Scanner - C Port for DSMIL DSSL */
/* Ported from HDAIS Python: ssh_access_with_scanner.py */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>

/* DSSL-based scanner logic integration would go here */
/* Since we already have ssh_scan_cve.c for the scanning part, */
/* this program focuses on the access/connection management aspect. */

#define MAX_CMD_LEN 2048
#define DEFAULT_PORT 22

void print_banner() {
    printf("================================================================================\n");
    printf("SSH ACCESS MANAGER (DSSL Port)\n");
    printf("Integrated with Vulnerability Scanner\n");
    printf("================================================================================\n\n");
}

void run_scanner(const char *target, int port) {
    printf("[*] Running integrated scanner (ssh_scan_cve)...");
    char cmd[MAX_CMD_LEN];
    /* Assumes ssh_scan_cve binary is in the same directory or PATH */
    snprintf(cmd, sizeof(cmd), "./ssh_scan_cve %s %d", target, port);
    system(cmd);
}

void establish_connection(const char *target, int port, const char *user, const char *key, int persistent) {
    printf("\n================================================================================\n");
    printf("ESTABLISHING %s SSH CONNECTION\n", persistent ? "PERSISTENT" : "TEST");
    printf("================================================================================\n\n");

    char cmd[MAX_CMD_LEN];
    char opts[512] = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null";
    
    if (persistent) {
        strcat(opts, " -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes");
    } else {
        strcat(opts, " -o ConnectTimeout=15");
    }

    char auth_part[512] = "";
    if (key) {
        snprintf(auth_part, sizeof(auth_part), "-i %s ", key);
    }

    char target_part[256];
    if (user) {
        snprintf(target_part, sizeof(target_part), "%s@%s", user, target);
    } else {
        snprintf(target_part, sizeof(target_part), "%s", target);
    }

    /* Construct command */
    snprintf(cmd, sizeof(cmd), "ssh %s -p %d %s %s", 
             opts, port, auth_part, target_part);

    if (!persistent) {
        /* Test command only */
        strcat(cmd, " \"echo 'Connection established successfully'\"");
    }

    printf("[*] Executing: %s\n", cmd);
    
    if (persistent) {
        printf("[*] Opening interactive session... (Press Ctrl+D to exit)\n");
        /* Use execvp to replace process with ssh for interactive session */
        /* Or system() to keep running wrapper */
        int ret = system(cmd);
        printf("\n[*] Session ended with code: %d\n", ret);
    } else {
        int ret = system(cmd);
        if (ret == 0) {
            printf("[+] Connection test PASSED\n");
        } else {
            printf("[!] Connection test FAILED (code: %d)\n", ret);
        }
    }
}

int main(int argc, char *argv[]) {
    char *target = NULL;
    int port = DEFAULT_PORT;
    char *user = NULL;
    char *key = NULL;
    int persistent = 0;
    int scan = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target> [-p port] [-u user] [-i identity_file] [--persistent] [--no-scan]\n", argv[0]);
        return 1;
    }

    target = argv[1];

    /* Simple argument parsing for C port */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            user = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--persistent") == 0) {
            persistent = 1;
        } else if (strcmp(argv[i], "--no-scan") == 0) {
            scan = 0;
        }
    }

    print_banner();

    if (scan) {
        run_scanner(target, port);
    }

    establish_connection(target, port, user, key, persistent);

    return 0;
}
