#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h> 
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 

#include "response_handler.h"
#include "mylib.h"
#include "myserver.h"


char *F_EXTENSIONS_IMAGE[] = {
	".jpeg",
	".jpg",
	".png",
	".bmp",
	".gif"
};

#define F_EXTENSIONS_IMAGE_LEN (sizeof(F_EXTENSIONS_IMAGE) / sizeof(char*))

char *FORWARD_DISABLED_PATHS[] = {
	"/static/"
};

#define FORWARD_DISABLED_PATHS_LEN (sizeof(FORWARD_DISABLED_PATHS) / sizeof(char*))


extern int errno;

extern long page_size;


void process_headers(struct request_attrs *req_attrs, char *request, char *http_method);

int extract_request_path(char query_path_buf[], char* query_string);

char * prepare_content_length_str(int payload_length);

char * allocate_buffer(size_t buf_size, int sess_socket_dscr, char* http_method, char *req_path, char *client_ip);

int respond_with_file(int sess_socket_dscr, struct request_attrs *req_attrs, char *http_method, char *client_ip, 
						bool is_keep_alive_session, double *last_client_data_exchange_timestamp);

bool send_response(int sess_socket_dscr, char *resp_arr[], int resp_arr_size, bool conn_keep_alive,
						double *last_client_data_exchange_timestamp, char *http_method, char *req_path, char *resp_code_str, char *client_ip);

bool must_forward(char *path);

int forward_req(int sess_socket_dscr, char *client_req_head_buf, size_t client_req_head_buf_size, char *client_req_body_buf, size_t client_req_body_buf_size, 
					char *http_method, char *req_path, char *client_ip);

int read_header_block(int sock_to_read_from, char *req_head_buf, char *head_buf_cursor, 
						int head_buf_size, int *header_length, int *header_terminator_length, char *http_method, 
						char *client_ip, double *last_data_exchange_timestamp, char *read_target);


size_t read_body_block(int sock_to_read_from, char *body_buf, char *body_start_ptr, 
									size_t body_bytes_read, struct request_attrs req_attrs, char *http_method, 
									char *client_ip, double *last_client_data_exchange_timestamp, char *read_target);




void request_loop(int sess_socket_dscr, char client_ip[]) {
	char http_method[REQ_INITIAL_CHUNK_SIZE];
	struct request_attrs req_attrs;
	
	bool is_keep_alive_session = false;
	double last_client_data_exchange_timestamp = 0;
	
	//for a Expected: Continue-100 case which sends body in separate chuked requests after initial req
	bool continue_chain_in_progress = false;
	
	char *continue_initial_head_buf = NULL;
	size_t continue_initial_head_total_size = 0;
	
	char *continue_req_body_buf_cursor = NULL;
	char *continue_req_body_buf = NULL;
	size_t continue_bytes_read_total = 0;
	size_t continue_content_length_total = 0;

	//loop listening for HTTP requests coming to assigned socket
	while (true) {

		/* READ REQUEST */
		
		/* if this is a Nth POST request after Expected: Continue-100 */
	
		if (continue_chain_in_progress) {

			//read request (expecting POST body)
			int bytes_read = recv_all(sess_socket_dscr, continue_req_body_buf_cursor, 
										continue_content_length_total - continue_bytes_read_total, &last_client_data_exchange_timestamp);
		
			if (bytes_read == -1) {
				syslog(LOG_ERR, "Failed to get data from body request after 100-Continue. Client IP: %s. Error: %s", client_ip, strerror(errno));
				
				free(continue_req_body_buf);
	
				return;
			}
			
			//100-continue subsequent request(s) are conducted via same socket so its like keep-alive session.
			//So if 0 bytes are received (no subsequent HTTP request received currently) - check for timeout
			if (bytes_read == 0) {
				int time_since_last_exchange = (int) (get_current_time() - last_client_data_exchange_timestamp);
				
				//if socket is not used for {timeout}sec (0 bytes are sent) - end process
				if (time_since_last_exchange > KEEP_ALIVE_TIMEOUT_SEC) {
					syslog(LOG_INFO, "Got no data, assuming keep alive timed out. Existing Client IP: %s", client_ip);
					
					return;
				} else {
				//else - continue and wait for next req
					sleep(1);
					continue;
				}
			}
		
			continue_req_body_buf_cursor += bytes_read;
			continue_bytes_read_total += bytes_read;
			
			//if already received whole body
			if (continue_bytes_read_total == continue_content_length_total) {
				syslog(LOG_NOTICE, "Got final body chunk after 'Expect: 100 Continue' request. Totally read %lu bytes. Client IP: '%s'", 
						continue_bytes_read_total, client_ip);
					
				int resp_result;
				
				/* if configured - forward req */
				if (must_forward(req_attrs.path)) {
					resp_result = forward_req(sess_socket_dscr, continue_initial_head_buf, continue_initial_head_total_size, 
												continue_req_body_buf, continue_content_length_total, http_method, req_attrs.path, client_ip);
				} else {
					/* if no forward configured - try to responde with file */

					resp_result = respond_with_file(sess_socket_dscr, &req_attrs, http_method, client_ip, 
														is_keep_alive_session, &last_client_data_exchange_timestamp);
				}
				
				free(continue_req_body_buf);
				free(continue_initial_head_buf);
				
				continue_chain_in_progress = false;
				
				continue_req_body_buf_cursor = NULL;
				continue_req_body_buf = NULL;
				continue_bytes_read_total = 0;
				continue_content_length_total = 0;
				
				continue_initial_head_buf = NULL;
				continue_initial_head_total_size = 0;

				//if responded normally and keep_alive - continue to listen for requests
				if (resp_result == 0 && is_keep_alive_session) {
					continue;
				} else {
					return;
				}
				
			} else {
				syslog(LOG_NOTICE, "Got Nth body chunk after 'Expect: 100 Continue' request. Already read %lu bytes. Waiting for next chunk. Client IP: '%s'", 
						continue_bytes_read_total, client_ip);
				respond_continue(sess_socket_dscr, http_method, req_attrs.path, client_ip, CONN_KEEP_ALIVE, &last_client_data_exchange_timestamp);
				
				continue;
			}
		}
		
		
		/* if this is a normal request (not a subsequent continue request) */
		size_t request_bytes_read = 0;
		
		//clear request buffers (are cross-req scopped to be used in subsequent 100-continue request(s))
		memset(http_method, 0, REQ_INITIAL_CHUNK_SIZE);
		memset(&req_attrs, 0, sizeof(req_attrs));
			
		//read first X bytes to figure http method
		
		char req_initial_chunk_buf[REQ_INITIAL_CHUNK_SIZE];
		memset(req_initial_chunk_buf, 0, REQ_INITIAL_CHUNK_SIZE);

		//read initial chunk (will contain http method and part of further request data)
		int bytes_read_initial = recv_all(sess_socket_dscr, req_initial_chunk_buf, REQ_INITIAL_CHUNK_SIZE, &last_client_data_exchange_timestamp);

		if (bytes_read_initial == -1) {
			if (is_keep_alive_session) {
				syslog(LOG_INFO, "Cant read 1st chunk from request. Probably keep-alive timed out. Client IP: %s. Error: %s", client_ip, strerror(errno));
			} else {
				syslog(LOG_ERR, "Failed to get 1st chunk of data from request. Client IP: %s. Error: %s", client_ip, strerror(errno));
			}
			
			return;
		}
		
		//if this is a keep-alive session and 0 bytes are received (no subsequent HTTP request received currently) - check for timeout
		if (is_keep_alive_session && bytes_read_initial == 0) {
			int time_since_last_exchange = (int) (get_current_time() - last_client_data_exchange_timestamp);
			
			//if socket is not used for {timeout}sec (0 bytes are sent) - end process
			if (time_since_last_exchange > KEEP_ALIVE_TIMEOUT_SEC) {
				syslog(LOG_INFO, "Got no data, assuming keep alive timed out. Existing Client IP: %s", client_ip);
				
				return;
			} else {
			//else - continue and wait for next req
				sleep(1);
				continue;
			}
		}
		
		//if any data received but its less than min initial chunk (i.e. less then minimum viable HTTP request)
		if (bytes_read_initial < REQ_INITIAL_CHUNK_SIZE) {
			syslog(LOG_ERR, "Failed to get minimal '%d' bytes as 1st chunk of data from request. Client IP: %s", REQ_INITIAL_CHUNK_SIZE, client_ip);
			respond_bad_request(sess_socket_dscr, http_method, NULL, client_ip, CONN_CLOSE, NULL);
			
			return;
		}
		
		//track read bytes with init header chunk
		request_bytes_read += bytes_read_initial;
		
		
		/* start request processing */
		
		figure_http_method(http_method, req_initial_chunk_buf, REQ_INITIAL_CHUNK_SIZE);
		
		//check method is allowed
		if (strcasecmp(http_method, HTTP_GET) != 0 && strcasecmp(http_method, HTTP_POST) != 0) {
			respond_method_not_allowed(sess_socket_dscr, NULL, http_method, client_ip, CONN_KEEP_ALIVE, &last_client_data_exchange_timestamp);

			continue;
		}

		//allocate buffer to hold head part. will contain header untill end marker \r\n\r\n and possibly part of following body
		char *req_head_buf = allocate_buffer(page_size, sess_socket_dscr, http_method, NULL, client_ip);
		
		if (req_head_buf == NULL) {	
			return;
		}

		//populate first X bytes of buffer with already retreived chunk
		memcpy(req_head_buf, req_initial_chunk_buf, REQ_INITIAL_CHUNK_SIZE);

		//then populate buffer with the rest of request untill header end identified
		
		/* read the rest of request to the remaining space of head buffer */
	
		char *head_buf_cursor = req_head_buf + REQ_INITIAL_CHUNK_SIZE;
		
		//last byte will remain '\0'
		int head_remaining_buf_size = (page_size - 1) - REQ_INITIAL_CHUNK_SIZE;	
		
		int header_length = -1,
			header_terminator_length = -1;
		
		//bytes read will be at least (header_length + header_terminator_length) but may be more (also got part or whole body)
		int bytes_read = read_header_block(sess_socket_dscr, req_head_buf, head_buf_cursor, head_remaining_buf_size, 
											&header_length, &header_terminator_length, http_method, client_ip, &last_client_data_exchange_timestamp, READ_TARGET_CLIENT);
		
		if (bytes_read < 0) {
			if (bytes_read == -2) {
				respond_header_too_large(sess_socket_dscr, http_method, NULL, client_ip);
			} else if (bytes_read == -3) {
				respond_request_timeout(sess_socket_dscr, http_method, NULL, client_ip, CONN_CLOSE, NULL);
			} else {
				respond_bad_request(sess_socket_dscr, http_method, NULL, client_ip, CONN_CLOSE, NULL);	
			}
				
			free(req_head_buf);
				
			return;
		}
		
		//append read bytes with the rest of header
		request_bytes_read += bytes_read;
		
		//string-terminate header for processing
		*(req_head_buf + header_length) = '\0';
		
		size_t header_total_size = (header_length + header_terminator_length);
		
		
		/* process headers */

		process_headers(&req_attrs, req_head_buf, http_method);

		if (strlen(req_attrs.error)) {
			syslog(LOG_ERR, "Error with headers parsing: %s", req_attrs.error);
			
			respond_bad_request(sess_socket_dscr, http_method, NULL, client_ip, CONN_CLOSE, NULL);
			free(req_head_buf);
			
			return;
		}
		
		//if keep-alive requested - start keep-alive session
		if (req_attrs.keep_alive) {
			is_keep_alive_session = true;
		}
		
		//if connection: close received - stop possible keep-alive session
		if (req_attrs.connection_close) {
			is_keep_alive_session = false;
		}
		
		syslog(LOG_INFO, "Got '%s' request, path: %s, keepalive: %d, accept: %s", http_method, req_attrs.path, is_keep_alive_session, req_attrs.accept);
			
		syslog(LOG_INFO, "Request header: %s", (req_head_buf == NULL ? "(null)" : req_head_buf));
			
		//check for "Expect: 100 Continue" header. If so - respond with 100 and wait for next requests carying body chunks
		if (strcasecmp(req_attrs.expect, HEADER_EXPECT_100_VAL) == 0) {
			if (!req_attrs.content_length) {
				respond_content_length_required(sess_socket_dscr, http_method, req_attrs.path, client_ip, CONN_KEEP_ALIVE, &last_client_data_exchange_timestamp);
				
				free(req_head_buf);
				
				continue;
			}
			
			continue_chain_in_progress = true;
			
			continue_initial_head_total_size = header_total_size;
			continue_initial_head_buf = allocate_buffer(page_size, sess_socket_dscr, http_method, NULL, client_ip);		
			
			if (continue_initial_head_buf == NULL) {	
				free(req_head_buf);
				
				return;
			}
			
			memcpy(continue_initial_head_buf, req_head_buf, page_size);
			
			continue_content_length_total = req_attrs.content_length;
			continue_req_body_buf = allocate_buffer(continue_content_length_total + 1, sess_socket_dscr, http_method, req_attrs.path, client_ip);
			
			if (continue_req_body_buf == NULL) {	
				free(req_head_buf);
				
				return;
			}
			
			continue_req_body_buf[continue_content_length_total] = '\0';
			continue_req_body_buf_cursor = continue_req_body_buf;
			
			syslog(LOG_NOTICE, "Got 'Expect: 100 Continue' request. Waiting for next req's with body chunks totaling %lu bytes. Client IP: '%s'", 
				continue_content_length_total, client_ip);
			
			respond_continue(sess_socket_dscr, http_method, req_attrs.path, client_ip, CONN_KEEP_ALIVE, &last_client_data_exchange_timestamp);
			
			free(req_head_buf);
			
			continue;
		}

		
		/* process req body if present*/
		
		char *req_body_buf = NULL;

		if (req_attrs.content_length > 0) {
			//possibly we already read part or whole body
			//request pipelining NOT supported, so anything after header is expected to be a body
			//this will point to either 1st byte of body or '\0' char if body isn't present
			char *body_start_ptr = (req_head_buf + header_total_size);
			
			size_t body_bytes_already_read = request_bytes_read - header_total_size;
			
			req_body_buf = allocate_buffer(req_attrs.content_length + 1, sess_socket_dscr, http_method, req_attrs.path, client_ip);
			
			if (req_body_buf == NULL) {
				free(req_head_buf);
				
				return;
			}
		
			req_body_buf[req_attrs.content_length] = '\0';

			int addit_body_bytes_read = read_body_block(sess_socket_dscr, req_body_buf, body_start_ptr, body_bytes_already_read, 
															req_attrs, http_method, client_ip, &last_client_data_exchange_timestamp, READ_TARGET_CLIENT);
			
			if (addit_body_bytes_read == -1) {
				respond_bad_request(sess_socket_dscr, http_method, req_attrs.path, client_ip, CONN_CLOSE, NULL);

				free(req_head_buf);
				free(req_body_buf);
				
				return;
			}

			//append read bytes with body
			request_bytes_read += addit_body_bytes_read;
			
			syslog(LOG_INFO, "Request length: %lu, BODY length: %lu", request_bytes_read, req_attrs.content_length);	
		}


		/* PREPARE PRESPONSE */
		
		int resp_result;
		
		/* if configured - forward req */
		if (must_forward(req_attrs.path)) {
			//revert insertion of string terminator into header buffer
			*(req_head_buf + header_length) = (header_terminator_length == 4 ? '\r' : '\n');
			
			resp_result = forward_req(sess_socket_dscr, req_head_buf, header_total_size, req_body_buf, req_attrs.content_length, 
										http_method, req_attrs.path, client_ip);
		} else {
			/* if no forward configured - try to responde with file */
			resp_result = respond_with_file(sess_socket_dscr, &req_attrs, http_method, client_ip, is_keep_alive_session, &last_client_data_exchange_timestamp);
		}
		
		free(req_head_buf);
		free(req_body_buf);
		
		//if responded normally and keep_alive - continue to listen for requests
		if (resp_result == 0 && is_keep_alive_session) {
			continue;
		} else {
			return;
		}
	}
}


int forward_req(int sess_socket_dscr, char *client_req_head_buf, size_t client_req_head_buf_size, char *client_req_body_buf, size_t client_req_body_buf_size, 
					char *http_method, char *req_path, char *client_ip) {

	syslog(LOG_INFO, "Forwarding '%s' request to %s:%d. ClientIP: %s", req_path, REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, client_ip);
	
	int rmt_socket_dscr = socket(AF_INET, SOCK_STREAM, 0);
    
    if (rmt_socket_dscr == -1) {
		syslog(LOG_ERR, "Error '%s' - failed to create socket while forwarding '%s' request to %s:%d. ClientIP: %s", 
			strerror(errno), req_path, REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, client_ip);
		
		respond_internal_error(sess_socket_dscr, http_method, req_path, client_ip, CONN_CLOSE, NULL);
		
		return -1;
	}
        
    struct hostent *rmt_server = gethostbyname(REMOTE_SERVER_HOST);
    
    if (rmt_server == NULL) {
		syslog(LOG_ERR, "Error '%s' - failed to identify hostname '%s' while forwarding '%s' request to %s:%d. ClientIP: %s", 
			strerror(errno), REMOTE_SERVER_HOST, req_path, REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, client_ip);
		
		respond_internal_error(sess_socket_dscr, http_method, req_path, client_ip, CONN_CLOSE, NULL);
		
		return -1;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    
    serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(REMOTE_SERVER_PORT);
    
    memcpy(&serv_addr.sin_addr.s_addr, rmt_server->h_addr, rmt_server->h_length);
   
    if (connect(rmt_socket_dscr, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
		syslog(LOG_ERR, "Error '%s' - failed to connect to remote server while forwarding '%s' request to %s:%d. ClientIP: %s", 
			strerror(errno), req_path, REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, client_ip);
		
		respond_bad_gateway(sess_socket_dscr, http_method, req_path, client_ip);
		
		return -1;
    }

	if (!send_all(rmt_socket_dscr, client_req_head_buf, client_req_head_buf_size)) {
		syslog(LOG_ERR, "Error '%s' - failed to send header data to remote server while forwarding '%s' request to %s:%d. ClientIP: %s", 
			strerror(errno), req_path, REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, client_ip);
		
		respond_gateway_timeout(sess_socket_dscr, http_method, req_path, client_ip);
		
		return -1;
	}
	
	if (client_req_body_buf_size > 0) {
		if (!send_all(rmt_socket_dscr, client_req_body_buf, client_req_body_buf_size)) {
			syslog(LOG_ERR, "Error '%s' - failed to send body data to remote server while forwarding '%s' request to %s:%d. ClientIP: %s", 
				strerror(errno), req_path, REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, client_ip);
			
			respond_gateway_timeout(sess_socket_dscr, http_method, req_path, client_ip);
			
			return -1;
		}
	}
	
	/* read remote server response */
	
	size_t rmt_resp_bytes_read = 0;
	
	//allocate buffer to hold head part. will contain header untill end marker \r\n\r\n and possibly part of following body
	char *rmt_resp_head_buf = allocate_buffer(page_size, sess_socket_dscr, http_method, req_path, client_ip);
	
	if (rmt_resp_head_buf == NULL) {	
		return -1;
	}
	
	/* read headers from remote server response */

	char *head_buf_cursor = rmt_resp_head_buf;
	
	//last byte will remain '\0'
	int head_remaining_buf_size = (page_size - 1);	
	
	int header_length = -1,
		header_terminator_length = -1;
	
	//bytes read will be at least (header_length + header_terminator_length) but may be more (also got part or whole body)
	int rmt_resp_head_bytes_read = read_header_block(rmt_socket_dscr, rmt_resp_head_buf, head_buf_cursor, head_remaining_buf_size, 
										&header_length, &header_terminator_length, http_method, client_ip, NULL, READ_TARGET_REMOTE_SERVER);
	
	if (rmt_resp_head_bytes_read < 0) {
		if (rmt_resp_head_bytes_read == -3) {
			respond_gateway_timeout(sess_socket_dscr, http_method, req_path, client_ip);
		} else {
			respond_bad_gateway(sess_socket_dscr, http_method, req_path, client_ip);
		}
		
		free(rmt_resp_head_buf);
			
		return -1;
	}
	
	//append read bytes with the rest of header
	rmt_resp_bytes_read += rmt_resp_head_bytes_read;
	
	size_t header_total_size = (header_length + header_terminator_length);
	
	
	/* process headers */
	struct request_attrs rmt_resp_attrs;
	memset(&rmt_resp_attrs, 0, sizeof(rmt_resp_attrs));
	
	process_headers(&rmt_resp_attrs, rmt_resp_head_buf, NULL);

	if (strlen(rmt_resp_attrs.error)) {
		syslog(LOG_ERR, "Error with remote response headers parsing: %s", rmt_resp_attrs.error);
		
		respond_bad_gateway(sess_socket_dscr, http_method, req_path, client_ip);
		free(rmt_resp_head_buf);
		
		return -1;
	}
	
	
	/* read body from remote server response (if present) */
		
	char *rmt_resp_body_buf = NULL;

	if (rmt_resp_attrs.content_length > 0) {
		//possibly we already read part or whole body
		//request pipelining NOT supported, so anything after header is expected to be a body
		//this will point to either 1st byte of body or '\0' char if body isn't present
		char *body_start_ptr = (rmt_resp_head_buf + header_total_size);
		
		size_t body_bytes_already_read = rmt_resp_bytes_read - header_total_size;
		
		rmt_resp_body_buf = allocate_buffer(rmt_resp_attrs.content_length + 1, sess_socket_dscr, http_method, rmt_resp_attrs.path, client_ip);
		
		if (rmt_resp_body_buf == NULL) {
			free(rmt_resp_head_buf);
			
			return -1;
		}

		rmt_resp_body_buf[rmt_resp_attrs.content_length] = '\0';

		int addit_body_bytes_read = read_body_block(rmt_socket_dscr, rmt_resp_body_buf, body_start_ptr, body_bytes_already_read, 
														rmt_resp_attrs, http_method, client_ip, NULL, READ_TARGET_REMOTE_SERVER);
		
		if (addit_body_bytes_read == -1) {
			syslog(LOG_ERR, "Error '%s' - failed to read whole body from remote server while forwarding '%s' request to %s:%d. ClientIP: %s", 
				strerror(errno), req_path, REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, client_ip);
			
			respond_bad_gateway(sess_socket_dscr, http_method, req_path, client_ip);
			
			free(rmt_resp_head_buf);
			free(rmt_resp_body_buf);
			
			return -1;
		}

		//append read bytes with body
		rmt_resp_bytes_read += addit_body_bytes_read;
		
		syslog(LOG_INFO, "Remote response length: %lu, BODY length: %lu", rmt_resp_bytes_read, rmt_resp_attrs.content_length);	
	}
	
	
	/* pass response back to client */
	
	if (!send_all(sess_socket_dscr, rmt_resp_head_buf, header_total_size)) {
		syslog(LOG_ERR, "Error while forwarding response remote server response headers to Client IP: %s. Error: %s", 
			client_ip, strerror(errno));
		
		free(rmt_resp_head_buf);
		free(rmt_resp_body_buf);
		
		return -1;
	}
	
	if (rmt_resp_attrs.content_length > 0) {
		if (!send_all(sess_socket_dscr, rmt_resp_body_buf, rmt_resp_attrs.content_length)) {
			syslog(LOG_ERR, "Error while forwarding response remote server response body to Client IP: %s. Error: %s", 
				client_ip, strerror(errno));
			
			free(rmt_resp_head_buf);
			free(rmt_resp_body_buf);
			
			return -1;
		}
	}

	free(rmt_resp_head_buf);
	free(rmt_resp_body_buf);

	syslog(LOG_ERR, "Forwarded '%s' request to %s:%d. ClientIP: %s", req_path, REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, client_ip);
	
	return 0;
}


/*
 * return: 0 if response was sent (file or 404 etc); -1 if error happened
 * */
int respond_with_file(int sess_socket_dscr, struct request_attrs *req_attrs, char *http_method, char *client_ip, 
						bool is_keep_alive_session, double *last_client_data_exchange_timestamp) {
	//assume request path leads to file
		
	char *file_name = "index.html";
	char file_path[512];

	//if any path requested and it isnt equal to'/' - use path as file path
	if (strlen(req_attrs->path) && strcasecmp(req_attrs->path, "/") != 0) {
		file_name = req_attrs->path;
	}

	strcpy(file_path, WEB_ROOT_FOLDER);
	if (WEB_ROOT_FOLDER[strlen(WEB_ROOT_FOLDER) - 1] != '/' && file_name[0] != '/') {
		strcat(file_path, "/");
	}
	strcat(file_path, file_name);

	struct stat file_stat;
	
	if (stat(file_path, &file_stat) == -1 || !S_ISREG(file_stat.st_mode)) {
		respond_not_found(sess_socket_dscr, http_method, req_attrs->path, client_ip, is_keep_alive_session, last_client_data_exchange_timestamp);
		
		return 0;
	}

	//read file (whole)
	char *file_buffer = allocate_buffer(file_stat.st_size, sess_socket_dscr, http_method, req_attrs->path, client_ip);
	char *file_cursor = file_buffer;
	
	if (file_buffer == NULL) {
		return -1;
	}
	
	int n;

	FILE *file_ptr = fopen(file_path,"rb");

	if (file_ptr == NULL) {
		respond_not_found(sess_socket_dscr, http_method, req_attrs->path, client_ip, is_keep_alive_session, last_client_data_exchange_timestamp);
		
		free(file_buffer);
		
		return 0;
	}
	
	int bytes_to_read = file_stat.st_size;
	while (bytes_to_read > 0) {
		size_t bytes_read = fread(file_cursor, sizeof(char), bytes_to_read, file_ptr);
		file_cursor += bytes_read;
		bytes_to_read -= bytes_read;
		
		if (feof(file_ptr) || ferror(file_ptr)) break;
	}
	
	fclose(file_ptr); 
	
	if (bytes_to_read > 0) {
		syslog(LOG_ERR, "Failed to read file: %s. ClientIP: %s. Error: %s", file_path, client_ip, strerror(errno));
		
		respond_internal_error(sess_socket_dscr, http_method, req_attrs->path, client_ip, is_keep_alive_session, last_client_data_exchange_timestamp);
		
		free(file_buffer);
		
		return 0;
	}
	
	
	/* prepare response */
	
	char *content_length_str = prepare_content_length_str(file_stat.st_size);
	
	if (content_length_str == NULL) {
		free(file_buffer);
		
		respond_internal_error(sess_socket_dscr, http_method, req_attrs->path, client_ip, CONN_CLOSE, NULL);
		
		return -1;
	}
	
	char content_type[256];
	figure_content_type(content_type, file_name);
	
	//set headers
	char *headers_arr[] = {
		RESP_HTTP_200,
		content_length_str,
		content_type,
		is_keep_alive_session ? HEADER_CONN_KEEP_ALIVE : HEADER_CONN_CLOSE,
		HEADER_SERVER,
		LINE_DELIM
	};
	
	char headers_str[256] = {0};
	
	concat_string_array(headers_str, headers_arr, (sizeof(headers_arr) / sizeof(char*)));
	
	int headers_length = (int) strlen(headers_str);
	
	//write headers
	if (send_all(sess_socket_dscr, headers_str, headers_length)) {
		syslog(LOG_NOTICE, "Responding to '%s' '%s' from '%s': %s", http_method, req_attrs->path, client_ip, headers_arr[0]);
		syslog(LOG_INFO, "Response headers: %s", headers_str);
		
		*last_client_data_exchange_timestamp = get_current_time();
	} else {
		syslog(LOG_ERR, "Error while sending headers to Client IP: %s. Error: %s", client_ip, strerror(errno));
		
		free(content_length_str);
		free(file_buffer);
		
		return -1;
	}
	
	//write file
	bool res = send_all(sess_socket_dscr, file_buffer, file_stat.st_size);
	
	free(content_length_str);
	free(file_buffer);
		
	if (res) {
		syslog(LOG_NOTICE, "Sent file payload to '%s' '%s' from '%s'. Content-Type: '%s' Size: %lu", http_method, req_attrs->path, client_ip, 
			content_type, (unsigned long) file_stat.st_size);
			
		*last_client_data_exchange_timestamp = get_current_time();
		
		return 0;
	} else {
		syslog(LOG_ERR, "Error while sending file payload to Client IP: %s. Error: %s", client_ip, strerror(errno));
		
		return -1;
	}
}


/*
* Reads header from socket untill header end (double-linebreak) is found. 
* returns amount of bytes read or -1 if error
*/
int read_header_block(int sock_to_read_from, char *req_head_buf, char *head_buf_cursor, 
						int head_buf_size, int *header_length, int *header_terminator_length, char *http_method, 
						char *client_ip, double *last_data_exchange_timestamp, char *read_target) {
	double time = get_current_time();

	int bytes_read = 0;
	while (*header_length == -1 && bytes_read < head_buf_size) {
		int recv_result = recv(sock_to_read_from, head_buf_cursor, head_buf_size - bytes_read, 0);
		
		//make sure request times out even if data comes but too slow
		int time_elapsed = (int) (get_current_time() - time);
		if (time_elapsed > SOCK_READ_TIMEOUT_SEC) {	
			return -3;
		}
		
		if (recv_result > 0) {
			if (last_data_exchange_timestamp != NULL) *last_data_exchange_timestamp = get_current_time();
		}

		if (recv_result < 1) {
			//continue if interrupted
			if (recv_result == -1 && errno == EINTR) {
				continue;
			} else {
				//error happened OR 0 bytes read (but we still didnt get whole header so this is also error)
				//logged below outside of cycle
				break;
			}
		}

		head_buf_cursor += recv_result;
		bytes_read += recv_result;
		
		//after each available data chunk read - try to find header end. Then -
		//set 0 string terminator right inside head bufer (instead of 1st linebreak),
		//determine where linebreaks are ending - used later to check if body is present after those breaks
		
		char *header_end_ptr = NULL;
		
		//HTTP specification-required breaks
		if ((header_end_ptr = strstr(req_head_buf, "\r\n\r\n")) != NULL) {
			*header_length = (header_end_ptr - req_head_buf);
			*header_terminator_length = 4;
			
		//fallback breaks
		} else if ((header_end_ptr = strstr(req_head_buf, "\n\n")) != NULL) {
			*header_length = (header_end_ptr - req_head_buf);
			*header_terminator_length = 2;
		}
	}
	
	//if failed to get/parse header - return error
	if (*header_length == -1) {
		if (bytes_read >= head_buf_size) {
			syslog(LOG_ERR, "Requset header buffer overflow from '%s'. Client IP: %s", read_target, client_ip);
			
			return -2;
		} else {
			syslog(LOG_ERR, "Connection error or cannot parse header from '%s'. Client IP: %s. Bytes read: %d, Error: %s", 
				read_target, client_ip, bytes_read, strerror(errno));
				
			return -1;
		}
	
	}
	
	return bytes_read;
}


size_t read_body_block(int sock_to_read_from, char *body_buf, char *body_start_ptr, 
									size_t body_bytes_read, struct request_attrs req_attrs, char *http_method, 
									char *client_ip, double *last_client_data_exchange_timestamp, char *read_target) {
	if (body_bytes_read > 0) {
		//populate first X bytes of buffer with already retreived data
		memcpy(body_buf, body_start_ptr, body_bytes_read);
	}
	//else would mean that we read exactly header and trailing line breaks, so body is yet to be read

	//if not whole body already read - try to read remainder
	size_t addit_body_bytes_read = 0;
	
	if (body_bytes_read < req_attrs.content_length) {
		addit_body_bytes_read = recv_all(sock_to_read_from, body_buf + body_bytes_read, 
									req_attrs.content_length - body_bytes_read, last_client_data_exchange_timestamp);
		if (addit_body_bytes_read == -1) {
			syslog(LOG_ERR, "Failed to get body data from '%s'. Client IP: %s. Error: %s", read_target, client_ip, strerror(errno));
			
			return -1;
		}
		
		if (body_bytes_read + addit_body_bytes_read < req_attrs.content_length) {
			syslog(LOG_ERR, "Failed to get full body data from '%s' (%lu of %lu). Client IP: %s", read_target, body_bytes_read, req_attrs.content_length, client_ip);
			
			return -1;
		}
		
		//else - now body buffer is filled
	}
	
	return addit_body_bytes_read;
}


void process_headers(struct request_attrs *req_attrs, char *req_headers, char *http_method_buf) {
    char *req_copy, *token_cursor, *nxt_token;
    
    req_copy = token_cursor = strdup(req_headers);
    
    if (req_copy == NULL) {
		strcpy(req_attrs->error, "Failed to strdup(req_headers)");
		
		return;
	}
    
    while ((nxt_token = strsep(&token_cursor, LINE_DELIM)) != NULL) {
        if (strlen(nxt_token)) {

            char token_lower[128] = {0};
            strcpy(token_lower, nxt_token);
            
            string_tolower(token_lower);
            
            if (http_method_buf != NULL && starts_with_str(token_lower, http_method_buf)) {
                //process query string. Path saved in original case
                if (!extract_request_path(req_attrs->path, nxt_token)) {
                    strcpy(req_attrs->error, "bad request path");

                    break;
                }

            //process headers 
            } else if (starts_with_str(token_lower, "accept")) {
                if (!get_header_value(req_attrs->accept, token_lower)) {
                    strcpy(req_attrs->error, "bad header: accept");

                    break;
                }
            } else if (starts_with_str(token_lower, "expect")) {
                if (!get_header_value(req_attrs->expect, token_lower)) {
                    strcpy(req_attrs->error, "bad header: expect");

                    break;
                }
            } else if (starts_with_str(token_lower, "content-length")) {
				char content_length_val[129] = {0};
				
                if (!get_header_value(content_length_val, token_lower)) {
                    strcpy(req_attrs->error, "bad header: content-length");

                    break;
                }
                req_attrs->content_length = strtoul(content_length_val, NULL, 10);
            } else if (starts_with_str(token_lower, "connection")) {
				char connection_val[64] = {0};
				
                if (!get_header_value(connection_val, token_lower)) {
                    strcpy(req_attrs->error, "bad header: connection");

                    break;
                }
                req_attrs->keep_alive = strcasecmp(connection_val, "keep-alive") == 0;
				req_attrs->connection_close = strcasecmp(connection_val, "close") == 0;
            }
        }
    }
    
    free(req_copy);
}


char * prepare_content_length_str(int payload_length) {
	char payload_length_str[129] = {0};
	int content_length_str_size;

	u_long_to_str(payload_length, payload_length_str, 10);
	
	//"Content-Length: \n\0" - 18 chars + room for content length number
	content_length_str_size = (18 + strlen(payload_length_str)) * sizeof(char);
	
	char *content_length_str = (char*) malloc(content_length_str_size);
	if (content_length_str == NULL) {
		syslog(LOG_ERR, "Failed to allocate memory for content_length_str. Message: %s", strerror(errno));
		return NULL;
	}
	
	memset(content_length_str, 0, content_length_str_size);
	
	strcat(content_length_str, "Content-Length: ");
	strcat(content_length_str, payload_length_str);
	strcat(content_length_str, "\n\0");
	
	//free after use
	return content_length_str;
}


int extract_request_path(char query_path_buf[], char* query_string) {
    char *path_str = NULL;
    
    int space_count = 0;
    
    int i;
    for (i = 0; i < strlen(query_string); i++) {
        char next_ch = *(query_string + i);
        
        if (isspace(next_ch)) {
            space_count++;
            
            //path starts after 1st space in request, ends at 2nd
            if (space_count == 1) {
                path_str = (query_string + i + 1);
            } else if (space_count == 2) {
                *(query_string + i) = '\0';
                
                break;
            }
        }
    }
    
    if (path_str != NULL) {
        strcpy(query_path_buf, path_str);

        return true;
    } else {
        return false;
    }
}


int recv_all(int socket, char *buf_ptr, size_t length, double *last_data_exchange_timestamp) {
	double time = get_current_time();
	int time_elapsed;
	
	int bytes_read = 0;
	
    while (length > 0) {
        int res = recv(socket, buf_ptr + bytes_read, length, 0);

		//make sure request times out even if data comes but too slow
		time_elapsed = (int) (get_current_time() - time);
		if (time_elapsed > SOCK_READ_TIMEOUT_SEC) {
			errno = ETIMEDOUT;
			
			return -1;
		}
			
        if (res == -1) {
			//continue if interrupted
			if (errno == EINTR) {
				continue;
			} else {
				return -1;
			}
		}
        
        if (res == 0) {
			break;
		} else {
			//some data received - remember current time
			if (last_data_exchange_timestamp != NULL) *last_data_exchange_timestamp = get_current_time();
		}

		bytes_read += res;
        length -= res;
    }
    
    return bytes_read;
}


bool send_all(int socket, char *buf_ptr, size_t length) {
    while (length > 0) {
        int res = send(socket, buf_ptr, length, 0);

        //continue if interrupted
        if (res == -1 && errno == EINTR) {
			continue;
		}
        
        if (res < 1) {
			return false;
		}

        buf_ptr += res;
        length -= res;
    }
    
    return true;
}


void respond_method_not_allowed(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip, 
									bool conn_keep_alive, double *last_client_data_exchange_timestamp) {
	char *resp_code_str = "405 Method Not Allowed";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
		HEADER_ALLOWED_METHODS,
	};

	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), conn_keep_alive, 
						last_client_data_exchange_timestamp, http_method, req_path, resp_code_str, client_ip);
}


void respond_internal_error(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip, 
								bool conn_keep_alive, double *last_client_data_exchange_timestamp) {
	char *resp_code_str = "500 Internal Server Error";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};

	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), conn_keep_alive, 
						last_client_data_exchange_timestamp, http_method, req_path, resp_code_str, client_ip);
}


void respond_gateway_timeout(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip) {
	char *resp_code_str = "504 Gateway Timeout";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), CONN_CLOSE, 
						 NULL, http_method, req_path, resp_code_str, client_ip);
}


void respond_bad_request(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip, 
							bool conn_keep_alive, double *last_client_data_exchange_timestamp) {
	char *resp_code_str = "400 Bad Request";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), conn_keep_alive, 
						last_client_data_exchange_timestamp, http_method, req_path, resp_code_str, client_ip);
}


void respond_bad_gateway(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip) {
	char *resp_code_str = "502 Bad Gateway";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), CONN_CLOSE, 
						NULL, http_method, req_path, resp_code_str, client_ip);
}


void respond_request_timeout(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip, 
								bool conn_keep_alive, double *last_client_data_exchange_timestamp) {
	char *resp_code_str = "408 Request Timeout";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), conn_keep_alive, 
						last_client_data_exchange_timestamp, http_method, req_path, resp_code_str, client_ip);
}


void respond_continue(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip, 
						bool conn_keep_alive, double *last_client_data_exchange_timestamp) {
	char *resp_code_str = "100 Continue";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), conn_keep_alive, 
						last_client_data_exchange_timestamp, http_method, req_path, resp_code_str, client_ip);
}


void respond_ok(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip, 
					bool conn_keep_alive, double *last_client_data_exchange_timestamp) {
	char *resp_code_str = "200 OK";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), conn_keep_alive, 
						last_client_data_exchange_timestamp, http_method, req_path, resp_code_str, client_ip);
}


void respond_not_found(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip, 
							bool conn_keep_alive, double *last_client_data_exchange_timestamp) {
	char *resp_code_str = "404 Not Found";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), conn_keep_alive, 
						last_client_data_exchange_timestamp, http_method, req_path, resp_code_str, client_ip);
}


void respond_content_length_required(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip, 
							bool conn_keep_alive, double *last_client_data_exchange_timestamp) {
	char *resp_code_str = "411 Length Required";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), conn_keep_alive, 
						last_client_data_exchange_timestamp, http_method, req_path, resp_code_str, client_ip);
}


void respond_insufficient_storage(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip) {
	char *resp_code_str = "507 Insufficient Storage";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), CONN_CLOSE, 
						 NULL, http_method, req_path, resp_code_str, client_ip);
}


void respond_header_too_large(int sess_socket_dscr, char *http_method, char *req_path, char *client_ip) {
	char *resp_code_str = "431 Request Header Fields Too Large";
	char *resp_arr[] = {
		"HTTP/1.1 ", resp_code_str, "\n",
	};
	
	send_response(sess_socket_dscr, resp_arr, (sizeof(resp_arr) / sizeof(char*)), CONN_CLOSE, 
						 NULL, http_method, req_path, resp_code_str, client_ip);
}


bool send_response(int sess_socket_dscr, char *resp_arr[], int resp_arr_size, bool conn_keep_alive, double *last_client_data_exchange_timestamp,
						char *http_method, char *req_path, char *resp_code_str, char *client_ip) {
	char *resp_tpl_arr[] = {
		"Content-Type: text/html\n",
		"Content-Length: 0\n",
		conn_keep_alive ? HEADER_CONN_KEEP_ALIVE : HEADER_CONN_CLOSE,
		HEADER_SERVER,
		"\n"
	};
	
	int resp_tpl_arr_size = (sizeof(resp_tpl_arr) / sizeof(char*));
	
	//join passed resp array and generic resp template
	int combined_resp_arr_size = resp_arr_size + resp_tpl_arr_size;
	char *combined_resp_arr[combined_resp_arr_size];
	
	int i;
	for (i = 0; i < resp_arr_size; i++) {
		combined_resp_arr[i] = resp_arr[i];
	}
	
	int ii;
	for (ii = 0; ii < resp_tpl_arr_size; ii++) {
		combined_resp_arr[i++] = resp_tpl_arr[ii];
	}
	
	
	//concat array to single string
	char resp_txt[512] = {0};
	concat_string_array(resp_txt, combined_resp_arr, combined_resp_arr_size);
	
	if (send_all(sess_socket_dscr, resp_txt, (int) strlen(resp_txt))) {
		syslog(LOG_NOTICE, "Responded to '%s' request, path '%s', returning '%s'. ClientIP: '%s'", 
					http_method, (req_path != NULL ? req_path : "(n/a)"), resp_code_str, client_ip);
		
		//keep-alive session continues, update timestamp
		if (last_client_data_exchange_timestamp != NULL) *last_client_data_exchange_timestamp = get_current_time();
		
		return true;
	} else {
		syslog(LOG_ERR, "Error while sending response '%s' to Client IP: %s. Error: %s", resp_code_str, client_ip, strerror(errno));
		
		return false;
	}
}


char * allocate_buffer(size_t req_size, int sess_socket_dscr, char* http_method, char *req_path, char *client_ip) {
	char *buf = (char*) malloc(req_size);
	
	if (buf == NULL) {
		syslog(LOG_ERR, "Failed to allocate memory (%lu bytes) for '%s' request. Client IP: %s, Message: %s", req_size, http_method, client_ip, strerror(errno));
		respond_insufficient_storage(sess_socket_dscr, http_method, req_path, client_ip);

		return NULL;
	}
	
	memset(buf, 0, req_size);
	
	return buf;
}


void figure_content_type(char content_type[], char *file_name) {
	if (ends_with_str(file_name, ".html")
			|| ends_with_str(file_name, ".htm")
			|| ends_with_str(file_name, ".txt")) {
		strcpy(content_type, HEADER_CONTENT_TYPE_TEXT_HTML);
		return;
	}
	
	if (ends_with_str(file_name, ".js")) {
		strcpy(content_type, HEADER_CONTENT_TYPE_TEXT_JS);
		return;
	}
	
	if (ends_with_str(file_name, ".css")) {
		strcpy(content_type, HEADER_CONTENT_TYPE_TEXT_CSS);
		return;
	}

	int i;
	for (i = 0; i < F_EXTENSIONS_IMAGE_LEN; i++) {
		//if image file
		if (ends_with_str(file_name, F_EXTENSIONS_IMAGE[i])) {
			strcpy(content_type, HEADER_CONTENT_TYPE_IMAGE);
			return;
		}
	}
	
	//if unknown
	strcpy(content_type, HEADER_CONTENT_TYPE_APP_OCTET_STREAM);
	
	return;
}


bool must_forward(char *path) {
	if (!FORWARD_ENABLED) {
		return false;
	}
	
	//check if forward is disabled for requested path
	int i;
	for (i = 0; i < FORWARD_DISABLED_PATHS_LEN; i++) {
		if (starts_with_str(path, FORWARD_DISABLED_PATHS[i])) {
			return false;
		}
	}
	
	return true;
}


