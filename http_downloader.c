/*
 * http_downloader.c
 *
 * COMMENTS HERE
 */

// define and include statements for functions needed to execute the program
#define _POSIX_C_SOURCE 200809L     // enables POSIX.1-2008 features in C library
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

// SSL/TLS functions and error reporting
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

// global variables for command line arguments
static char *url = NULL;
static int num_parts = 0;
static char *output_file = NULL;