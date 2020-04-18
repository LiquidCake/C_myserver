#include <stdbool.h>


#define LINE_DELIM "\r\n"

#define HTTP_GET "GET"
#define HTTP_POST "POST"

#define RESP_HTTP_200 "HTTP/1.1 200 OK" LINE_DELIM

#define HEADER_SERVER "Server: myserver" LINE_DELIM
#define HEADER_ALLOWED_METHODS "Allow: GET, POST" LINE_DELIM
#define HEADER_CONN_KEEP_ALIVE "Connection: Keep-Alive" LINE_DELIM
#define HEADER_CONN_CLOSE "Connection: close" LINE_DELIM

#define HEADER_CONTENT_TYPE_TEXT_HTML "Content-Type: text/html" LINE_DELIM
#define HEADER_CONTENT_TYPE_TEXT_JS "Content-Type: text/javascript" LINE_DELIM
#define HEADER_CONTENT_TYPE_TEXT_CSS "Content-Type: text/css" LINE_DELIM
#define HEADER_CONTENT_TYPE_IMAGE "Content-Type: image" LINE_DELIM
#define HEADER_CONTENT_TYPE_APP_OCTET_STREAM "Content-Type: application/octet-stream" LINE_DELIM

#define HEADER_EXPECT_100_VAL "100-Continue"

#define CONN_KEEP_ALIVE 1
#define CONN_CLOSE 0

#define REQ_INITIAL_CHUNK_SIZE 10

#define READ_TARGET_REMOTE_SERVER "remote server"
#define READ_TARGET_CLIENT "client"

struct request_attrs {
    char path[1024];
    char accept[256];
    char expect[256];
    unsigned long content_length;
    bool keep_alive;
	bool connection_close;
    
    char error[128];
};


void request_loop(int session_dscr, char client_ip[]);

void respond_method_not_allowed(int session_dscr, char *http_method, char *req_path, char *client_ip, 
									bool conn_keep_alive, double *last_data_exchange_timestamp);

void respond_gateway_timeout(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip);
								
void respond_bad_request(int session_dscr, char *http_method, char *req_path, char *client_ip, 
							bool conn_keep_alive, double *last_data_exchange_timestamp);

void respond_request_timeout(int session_dscr, char *http_method, char *req_path, char *client_ip, 
								bool conn_keep_alive, double *last_data_exchange_timestamp);

void respond_internal_error(int session_dscr, char *http_method, char *req_path, char *client_ip, 
								bool conn_keep_alive, double *last_data_exchange_timestamp);

void respond_continue(int session_dscr, char *http_method, char *req_path,char *client_ip, 
							bool conn_keep_alive, double *last_data_exchange_timestamp);

void respond_ok(int session_dscr, char *http_method, char *req_path,char *client_ip, 
					bool conn_keep_alive, double *last_data_exchange_timestamp);

void respond_not_found(int session_dscr, char *http_method, char *req_path, char *client_ip, 
							bool conn_keep_alive, double *last_data_exchange_timestamp);
							
void respond_content_length_required(int session_dscr, char *http_method, char *req_path, char *client_ip, 
							bool conn_keep_alive, double *last_data_exchange_timestamp);
							
void respond_insufficient_storage(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip);

void respond_header_too_large(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip);

void respond_bad_gateway(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip);

int recv_all(int socket, char *buf_ptr, size_t length, double *last_data_exchange_timestamp);

bool send_all(int socket, char *buf_ptr, size_t length);

void figure_content_type(char content_type[], char *file_name);

