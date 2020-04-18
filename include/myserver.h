#include <stdbool.h>


#define DEFAULT_PORT "8080"

#define WEB_ROOT_FOLDER "/home/arseniy/work/edu/akhangaldyan-pth01"
#define FORWARD_ENABLED true

#define REMOTE_SERVER_HOST "127.0.0.1"
#define REMOTE_SERVER_PORT 8000

#define SOCK_READ_TIMEOUT_SEC 60
#define KEEP_ALIVE_TIMEOUT_SEC 60

#define SOCKET_QUEUE_LIMIT 100


bool set_sock_options (int server_socket_dscr);
