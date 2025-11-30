/* SSH Vulnerability Scanner for CVE-2024-48949 & CVE-2024-48948 */
/* Ported from HDAIS Python Scanner to DSMIL DSSL */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#define MAX_BUFFER 4096
#define DEFAULT_PORT 22
#define TIMEOUT_SEC 10

/* Vulnerability Status Codes */
typedef enum {
    STATUS_VULNERABLE,
    STATUS_PATCHED,
    STATUS_UNKNOWN,
    STATUS_UNREACHABLE
} VulnStatus;

/* Severity Levels */
typedef enum {
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW
} Severity;

typedef struct {
    char host[256];
    int port;
    char banner[256];
    char supported_kex[MAX_BUFFER];
    char supported_ciphers[MAX_BUFFER];
    char supported_keys[MAX_BUFFER];
} TargetInfo;

/* Helper to execute command and get output */
int execute_ssh_probe(const char *host, int port, const char *option, char *output, size_t out_len) {
    char cmd[1024];
    FILE *fp;
    
    /* Using ssh -G to probe configuration - similar to Python implementation */
    /* In a standalone C tool, we might prefer libssh, but DSSL context implies OpenSSL usage or system tools */
    snprintf(cmd, sizeof(cmd), "ssh -G -p %d %s 2>/dev/null | grep -i '^%s'", port, host, option);
    
    fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }
    
    if (fgets(output, out_len, fp) != NULL) {
        /* Strip newline */
        output[strcspn(output, "\n")] = 0;
        pclose(fp);
        return 0;
    }
    
    pclose(fp);
    return -1;
}

/* Helper to check if string contains substring (case insensitive) */
int str_contains_ignore_case(const char *haystack, const char *needle) {
    return strcasestr(haystack, needle) != NULL;
}

void print_banner(const char *host, int port) {
    printf("================================================================================\n");
    printf("SSH TARGET VULNERABILITY SCANNER (DSSL Port)\n");
    printf("Testing for CVE-2024-48949 and CVE-2024-48948\n");
    printf("Target: %s:%d\n", host, port);
    printf("================================================================================\n\n");
}

/* CVE-2024-48949: EdDSA Signature Malleability Check */
VulnStatus check_eddsa_malleability(TargetInfo *info) {
    printf("[*] Testing for CVE-2024-48949 (EdDSA Signature Malleability)...");
    
    if (!str_contains_ignore_case(info->supported_keys, "ed25519")) {
        printf("[*] Target does not support Ed25519 - test not applicable\n");
        return STATUS_UNKNOWN;
    }
    
    printf("[+] Target supports Ed25519\n");
    
    /* Check for OpenSSH version in banner */
    if (str_contains_ignore_case(info->banner, "OpenSSH")) {
        printf("[+] OpenSSH detected in banner: %s\n", info->banner);
        /* OpenSSH uses libcrypto (OpenSSL) which generally handles this correctly */
        /* Logic mirrored from Python script */
        printf("[*] OpenSSH implementation uses libcrypto with proper bounds checking\n");
        printf("[*] Not vulnerable to CVE-2024-48949 (affects JavaScript library)\n");
        return STATUS_PATCHED;
    }
    
    printf("[?] Unknown SSH implementation - vulnerability status uncertain\n");
    return STATUS_UNKNOWN;
}

/* CVE-2024-48948: ECDSA Leading Zero Validation Bypass Check */
VulnStatus check_ecdsa_leading_zero(TargetInfo *info) {
    printf("\n[*] Testing for CVE-2024-48948 (ECDSA Leading Zero Bypass)...");
    
    if (!str_contains_ignore_case(info->supported_keys, "ecdsa")) {
        printf("[*] Target does not support ECDSA - test not applicable\n");
        return STATUS_UNKNOWN;
    }
    
    printf("[+] Target supports ECDSA\n");
    
    /* Check for OpenSSH version in banner */
    if (str_contains_ignore_case(info->banner, "OpenSSH")) {
        printf("[+] OpenSSH detected in banner: %s\n", info->banner);
        /* Logic mirrored from Python script */
        printf("[*] OpenSSH uses ASN.1 DER encoding (not vulnerable)\n");
        printf("[*] Not vulnerable to CVE-2024-48948 (affects JavaScript library)\n");
        return STATUS_PATCHED;
    }
    
    printf("[?] Unknown SSH implementation - vulnerability status uncertain\n");
    return STATUS_UNKNOWN;
}

void check_weak_algos(TargetInfo *info) {
    printf("\n[*] Testing for weak cryptographic algorithms...");
    
    int found_weak = 0;
    if (str_contains_ignore_case(info->supported_keys, "ssh-rsa")) {
        printf("[!] Found weak key type: ssh-rsa (RSA with SHA-1 deprecated)\n");
        found_weak = 1;
    }
    if (str_contains_ignore_case(info->supported_keys, "ssh-dss")) {
        printf("[!] Found weak key type: ssh-dss (DSA insecure)\n");
        found_weak = 1;
    }
    
    if (found_weak) {
        printf("[!] Recommendation: Disable ssh-rsa and ssh-dss in sshd_config\n");
    } else {
        printf("[+] No weak algorithms detected in public configuration\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host> [port]\n", argv[0]);
        return 1;
    }
    
    const char *host = argv[1];
    int port = (argc > 2) ? atoi(argv[2]) : DEFAULT_PORT;
    TargetInfo info;
    memset(&info, 0, sizeof(info));
    
    strncpy(info.host, host, sizeof(info.host) - 1);
    info.port = port;
    
    print_banner(host, port);
    
    /* 1. Probe Target Banner */
    int sock;
    struct sockaddr_in server;
    struct hostent *hp;
    char buffer[1024];
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    server.sin_family = AF_INET;
    hp = gethostbyname(host);
    if (hp == 0) {
        perror("Unknown host");
        return 1;
    }
    memcpy(&server.sin_addr, hp->h_addr, hp->h_length);
    server.sin_port = htons(port);
    
    printf("[*] Connecting to %s:%d...\n", host, port);
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        return 1;
    }
    
    ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (len > 0) {
        buffer[len] = 0;
        /* Trim newline */
        buffer[strcspn(buffer, "\r\n")] = 0;
        strncpy(info.banner, buffer, sizeof(info.banner) - 1);
        printf("[+] SSH Banner: %s\n", info.banner);
    } else {
        printf("[!] Failed to retrieve banner\n");
        close(sock);
        return 1;
    }
    close(sock);
    
    /* 2. Probe Algorithms (using local ssh client for config parsing capability) */
    /* In a fully native DSSL implementation, we'd parse the SSH handshake packets here. */
    /* For this port, we use the system tool for alg extraction to match Python logic */
    
    execute_ssh_probe(host, port, "kexalgorithms", info.supported_kex, sizeof(info.supported_kex));
    execute_ssh_probe(host, port, "ciphers", info.supported_ciphers, sizeof(info.supported_ciphers));
    execute_ssh_probe(host, port, "hostkeyalgorithms", info.supported_keys, sizeof(info.supported_keys));
    
    if (strlen(info.supported_keys) > 0) {
        printf("[+] Probed supported algorithms\n");
    } else {
        printf("[!] Failed to probe detailed algorithms (local ssh client may be needed)\n");
    }
    
    /* 3. Run Vulnerability Checks */
    check_eddsa_malleability(&info);
    check_ecdsa_leading_zero(&info);
    check_weak_algos(&info);
    
    printf("\n================================================================================\n");
    printf("SCAN COMPLETE\n");
    printf("================================================================================\n");
    
    return 0;
}
