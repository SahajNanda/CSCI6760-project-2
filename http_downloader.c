#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
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

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s -u <URL> -n <num_parts> -o <output_file>\n", program_name);
    fprintf(stderr, "  -u <URL>         URL to download\n");
    fprintf(stderr, "  -n <num_parts>   Number of parts to split download into\n");
    fprintf(stderr, "  -o <output_file> Output file name\n");
}

int parse_arguments(int argc, char *argv[]) {
    int opt;
    
    optind = 1;
    
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
                print_usage(argv[0]);
                return 1;
            case '?':
                fprintf(stderr, "Error: Unknown option or missing argument\n");
                print_usage(argv[0]);
                return -1;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    
    if (!url || num_parts == 0 || !output_file) {
        fprintf(stderr, "Error: All options -u, -n, and -o are required\n");
        print_usage(argv[0]);
        return -1;
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
    
    printf("URL: %s\n", url);
    printf("Number of parts: %d\n", num_parts);
    printf("Output file: %s\n", output_file);
    
    
    if (url) {
        free(url);
    }
    if (output_file) {
        free(output_file);
    }
    
    return 0;
}