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
} // print_usage

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
        } // switch
    } // while
    
    if (!url || num_parts == 0 || !output_file) {
        fprintf(stderr, "Error: All options -u, -n, and -o are required\n");
        print_usage();
        return -1;
    } // if
    
    return 0;
} // parse_arguments

int parseURL(const char *url, char *host, char *path) {
    if (strncmp(url, "https://", 8) != 0) {
        fprintf(stderr, "Error: Only HTTPS URLs are supported\n");
        return -1;
    } // if
    
    const char *url_start = url + 8; // skip "https://"
    const char *path_start = strchr(url_start, '/');
    
    if (path_start) {
        size_t host_len = path_start - url_start;
        if (host_len >= MAX_HOST) {
            fprintf(stderr, "Error: Hostname too long\n");
            return -1;
        } // if
        strncpy(host, url_start, host_len);
        host[host_len] = '\0';
        
        if (strlen(path_start) >= MAX_PATH) {
            fprintf(stderr, "Error: Path too long\n");
            return -1;
        } // if
        strcpy(path, path_start);
    } else {
        if (strlen(url_start) >= MAX_HOST) {
            fprintf(stderr, "Error: Hostname too long\n");
            return -1;
        } // if
        strcpy(host, url_start);
        strcpy(path, "/");
    } // if-else
    
    return 0;
} // parseURL

void * download_part(void *arg) {
    part_arg_t *p = (part_arg_t *)arg;
    char request[MAX_REQ];
    char response[BUF_SZ];
    int n, retries = 0;
    char temp_file[64];
    snprintf(temp_file, sizeof(temp_file), "part_%d", p->index + 1);
    
    while (retries < MAX_RETRIES) {
        int sockfd;
        struct hostent *server;
        struct sockaddr_in serv_addr;

        // resolve hostname
        server = gethostbyname(p->host);
        if (!server) {
            pthread_mutex_lock(p->print_lock);
            fprintf(stderr, "Thread %d: ERROR: no such host\n", p->index);
            pthread_mutex_unlock(p->print_lock);
            retries++;
            continue;
        } // if

        // create tcp socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            pthread_mutex_lock(p->print_lock);
            perror("Thread: ERROR opening socket");
            pthread_mutex_unlock(p->print_lock);
            retries++;
            continue;
        } // if

        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(443);  // HTTPS
        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

        // connect tcp
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            pthread_mutex_lock(p->print_lock);
            perror("Thread: ERROR connecting");
            pthread_mutex_unlock(p->print_lock);
            close(sockfd);
            retries++;
            continue;
        } // if

        // wrap socket in tls
        SSL *ssl = SSL_new(p->ssl_ctx);
        SSL_set_fd(ssl, sockfd);

        if (SSL_connect(ssl) <= 0) {
            pthread_mutex_lock(p->print_lock);
            ERR_print_errors_fp(stderr);
            pthread_mutex_unlock(p->print_lock);
            SSL_free(ssl);
            close(sockfd);
            retries++;
            continue;
        } // if

        // build http get request with range header
        snprintf(request, MAX_REQ,
                 "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%ld-%ld\r\nConnection: close\r\n\r\n",
                 p->path, p->host, p->start, p->end);

        // send request
        SSL_write(ssl, request, strlen(request));

        // open temp file for writing
        FILE *out = fopen(temp_file, "wb");
        if (!out) {
            pthread_mutex_lock(p->print_lock);
            perror("Thread: ERROR opening temp file");
            pthread_mutex_unlock(p->print_lock);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            retries++;
            continue;
        } // if

        // read response
        int header_parsed = 0;
        p->bytes_written = 0;   // reset bytes_written for each retry
        while ((n = SSL_read(ssl, response, sizeof(response))) > 0) {
            if (!header_parsed) {
                char *header_end = strstr(response, "\r\n\r\n");
                if (header_end) {
                    size_t header_len = header_end - response + 4;
                    fwrite(header_end + 4, 1, n - header_len, out);
                    p->bytes_written += n - header_len;
                    header_parsed = 1;
                } // if
            } else {
                fwrite(response, 1, n, out);
                p->bytes_written += n;
            } // if-else
        } // while

        if (n < 0) {
            pthread_mutex_lock(p->print_lock);
            ERR_print_errors_fp(stderr);
            pthread_mutex_unlock(p->print_lock);
            fclose(out);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            retries++;
            continue;
        } // if

        fclose(out);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        p->success = 1;
        pthread_mutex_lock(p->print_lock);
        printf("Thread %d: Downloaded %ld bytes to %s\n", p->index, p->bytes_written, temp_file);
        pthread_mutex_unlock(p->print_lock);
        return NULL;
    } // while

    pthread_mutex_lock(p->print_lock);
    fprintf(stderr, "Thread %d: Failed to download after %d retries\n", p->index, MAX_RETRIES);
    pthread_mutex_unlock(p->print_lock);
    p->success = 0;
    return NULL;
} // download_part

int main(int argc, char *argv[]) {
    int parse_result = parse_arguments(argc, argv);
    if (parse_result != 0) {
        if (parse_result == 1) {
            return 0;
        }
        return 1;
    } // if

    char host[MAX_HOST];
    char path[MAX_PATH];
    if (parseURL(url, host, path) != 0) {
        if (url) {
            free(url);
        } // if
        if (output_file) {
            free(output_file);
        } // if
        return 1;
    } // if
    
    printf("URL: %s\n", url);
    printf("Number of parts: %d\n", num_parts);
    printf("Output file: %s\n", output_file);

    int sockfd;
    struct hostent *server;
    struct sockaddr_in serv_addr;
    char request[1024], response[8192];
    int n;

    // initialize openssl
    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    } // if

    // resolve hostname 
    server = gethostbyname(host);
    if (!server) {
        fprintf(stderr, "ERROR: no such host\n");
        return 1;
    } // if

    // create tcp socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        return 1;
    } // if

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(443);  // HTTPS
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

    // connect tcp 
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        return 1;
    } // if

    // wrap socket in tls 
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    } // if

    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

    // build http head request
    snprintf(request, MAX_REQ,
             "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
             path, host);

    // send request
    SSL_write(ssl, request, strlen(request));

    // read response 
    memset(response, 0, sizeof(response));
    n = SSL_read(ssl, response, sizeof(response) - 1);
    if (n <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Response headers:\n%s\n", response);

        // look for content-length
        char *cl = strstr(response, "Content-Length:");
        if (cl) {
            long length = atol(cl + 15);  // skip "Content-Length:"
            printf("Content-Length = %ld bytes\n", length);
        } else {
            printf("Content-Length not found.\n");
        } // if-else
    } // if-else

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);

    // launch threads to download parts
    pthread_t threads[num_parts];
    part_arg_t parts[num_parts];
    pthread_mutex_t print_lock;
    pthread_mutex_init(&print_lock, NULL);
    long part_size = 0; // assume we got content-length from above
    char *cl = strstr(response, "Content-Length:");
    long length = 0;
    if (cl) {
        length = atol(cl + 15);  // skip "Content-Length:"
        part_size = length / num_parts;
    } else {
        fprintf(stderr, "Error: Content-Length not found, cannot split download\n");
        SSL_CTX_free(ctx);
        return 1;
    } // if-else

    for (int i = 0; i < num_parts; i++) {
        strncpy(parts[i].host, host, MAX_HOST);
        strncpy(parts[i].port, "443", MAX_PORT);
        strncpy(parts[i].path, path, MAX_PATH);
        parts[i].start = i * part_size;
        parts[i].end = (i == num_parts - 1) ? (parts[i].start + part_size + (length % num_parts) - 1) : (parts[i].start + part_size - 1);
        parts[i].index = i;
        parts[i].ssl_ctx = ctx;
        parts[i].print_lock = &print_lock;
        parts[i].success = 0;
        parts[i].bytes_written = 0;

        if (pthread_create(&threads[i], NULL, download_part, &parts[i]) != 0) {
            perror("Error creating thread");
            SSL_CTX_free(ctx);
            return 1;
        } // if
    } // for

    // wait for threads to finish
    for (int i = 0; i < num_parts; i++) {
        pthread_join(threads[i], NULL);
        if (!parts[i].success) {
            fprintf(stderr, "Error: Part %d failed to download\n", i);
            SSL_CTX_free(ctx);
            return 1;
        } // if
    } // for

    pthread_mutex_destroy(&print_lock);
    SSL_CTX_free(ctx);

    // combine parts into output file
    FILE *combined_final = fopen(output_file, "wb");
    if (!combined_final) {
        perror("Error opening output file");
        return 1;
    } // if
    for (int i = 0; i < num_parts; i++) {
        char temp_file[64];
        snprintf(temp_file, sizeof(temp_file), "part_%d", i + 1);
        FILE *part_file = fopen(temp_file, "rb");
        if (!part_file) {
            perror("Error opening part file");
            fclose(combined_final);
            return 1;
        } // if

        while ((n = fread(response, 1, sizeof(response), part_file)) > 0) {
            fwrite(response, 1, n, combined_final);
        } // while

        fclose(part_file);
    } // for

    printf("Download complete: %s\n", output_file);
    
    fclose(combined_final);
    
    if (url) {
        free(url);
    } // if
    if (output_file) {
        free(output_file);
    } // if
    
    return 0;
} // main