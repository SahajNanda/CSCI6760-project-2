#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <inttypes.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// defining buffer sizes to prevent overflows
#define BUF_SZ 16834        // size of buffer when reading from SSL connection
#define MAX_HOST 512        // max length for hostname string
#define MAX_PATH 2048       // max length for URL path
#define MAX_REQ 4096        // max length for HTTP request string
#define MAX_PORT 8          // max length for port string
#define MAX_RETRIES 3       // max retry attempts

// thread struct
typedef struct {
    char host[MAX_HOST];    // URL components for request
    char port[MAX_PORT];
    char path[MAX_PATH];
    long start;             // byte range
    long end;
    int index;              // keep track of part num
    SSL_CTX *ssl_ctx;       // share SSL content among threads
    pthread_mutex_t *print_lock;    // sync printf across threads
    int success;            // indicate if download was successful
    long bytes_written;     // num of bytes written by this particular thread
} part_arg_t;

static char *url = NULL;
static int num_parts = 0;
static char *output_file = NULL;

void print_usage() {
    fprintf(stderr, "Usage: ./http_downloader -u <URL> -n <num_parts> -o <output_file>\n");
    fprintf(stderr, "  -u <URL>         URL to download\n");
    fprintf(stderr, "  -n <num_parts>   Number of parts to split download into\n");
    fprintf(stderr, "  -o <output_file> Output file name\n");
}

int parse_arguments(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "u:n:o:h")) != -1) {
        switch (opt) {
            case 'u':
                url = strdup(optarg);
                if (!url) {
                    fprintf(stderr, "Error: Failed to allocate memory for URL\n");
                    return -1;
                }
                break;
            case 'n':
                num_parts = atoi(optarg);
                if (num_parts <= 0) {
                    fprintf(stderr, "Error: Number of parts must be a positive integer\n");
                    return -1;
                }
                break;
            case 'o':
                output_file = strdup(optarg);
                if (!output_file) {
                    fprintf(stderr, "Error: Failed to allocate memory for output filename\n");
                    return -1;
                }
                break;
            case 'h':
                print_usage();
                return 1;
            case '?':
                fprintf(stderr, "Error: Unknown option or missing argument\n");
                print_usage();
                return -1;
            default:
                print_usage();
                return -1;
        }
    }
    
    if (!url || num_parts == 0 || !output_file) {
        fprintf(stderr, "Error: All options -u, -n, and -o are required\n");
        print_usage();
        return -1;
    }
    
    return 0;
}

int parseURL(const char *url, char *host, char *path) {
    if (strncmp(url, "https://", 8) != 0) {
        fprintf(stderr, "Error: Only HTTPS URLs are supported\n");
        return -1;
    }
    
    const char *url_start = url + 8; // skip "https://"
    const char *path_start = strchr(url_start, '/');
    
    if (path_start) {
        size_t host_len = path_start - url_start;
        if (host_len >= MAX_HOST) {
            fprintf(stderr, "Error: Hostname too long\n");
            return -1;
        }
        strncpy(host, url_start, host_len);
        host[host_len] = '\0';
        
        if (strlen(path_start) >= MAX_PATH) {
            fprintf(stderr, "Error: Path too long\n");
            return -1;
        }
        strcpy(path, path_start);
    } else {
        if (strlen(url_start) >= MAX_HOST) {
            fprintf(stderr, "Error: Hostname too long\n");
            return -1;
        }
        strcpy(host, url_start);
        strcpy(path, "/");
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int parse_result = parse_arguments(argc, argv);
    if (parse_result != 0) {
        if (parse_result == 1) {
            return 0;
        }
        return 1;
    }

    char host[MAX_HOST];
    char path[MAX_PATH];
    if (parseURL(url, host, path) != 0) {
        if (url) {
            free(url);
        }
        if (output_file) {
            free(output_file);
        }
        return 1;
    }
    
    printf("URL: %s\n", url);
    printf("Number of parts: %d\n", num_parts);
    printf("Output file: %s\n", output_file);

    int sockfd;
    struct hostent *server;
    struct sockaddr_in serv_addr;
    char request[1024], response[8192];
    int n;

    // ---------- Initialize OpenSSL ----------
    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // ---------- Resolve hostname ----------
    server = gethostbyname(host);
    if (!server) {
        fprintf(stderr, "ERROR: no such host\n");
        return 1;
    }

    // ---------- Create TCP socket ----------
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        return 1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(443);  // HTTPS
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

    // ---------- Connect TCP ----------
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        return 1;
    }

    // ---------- Wrap socket in TLS ----------
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

    // ---------- Build HTTP HEAD request ----------
    snprintf(request, sizeof(request),
             "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
             path, host);

    // ---------- Send request ----------
    SSL_write(ssl, request, strlen(request));

    // ---------- Read response ----------
    memset(response, 0, sizeof(response));
    n = SSL_read(ssl, response, sizeof(response) - 1);
    if (n <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Response headers:\n%s\n", response);

        // ---------- Look for Content-Length ----------
        char *cl = strcasestr(response, "Content-Length:");
        if (cl) {
            long length = atol(cl + 15);  // skip "Content-Length:"
            printf("Content-Length = %ld bytes\n", length);
        } else {
            printf("Content-Length not found.\n");
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    
    
    if (url) {
        free(url);
    }
    if (output_file) {
        free(output_file);
    }
    
    return 0;
}