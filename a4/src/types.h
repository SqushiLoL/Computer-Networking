#include "common.h"

// an enum that represents wether to shutdown server thread
typedef enum { SHUTDOWN = 0, DONT_SHUTDOWN = 1 } ShutdownState_t;

typedef enum { WARNING = 0, INFO = 1, ERROR = 2 } LogLevel_t;

typedef enum { PEER_EQUAL = 0, PEER_NOT_EQUAL = 1 } PeerComparisonResult_t;

typedef enum { PEER_EXISTS = 0, PEER_NOT_EXISTS = 1 } PeerExistenceStatus_t;

typedef enum { ADJUST_OK = 0, ADJUST_FAIL = 1 } AdjustResult_t;

typedef enum {
  PEER_APPEND_SUCCESS = 1,
  PEER_ALREADY_EXISTS = 0,
  PEER_APPEND_ERROR   = -1
} PeerAppendStatus_t;

typedef struct {
  uint32_t command;
  char     msg_buffer[MAX_MSG_LEN];
  char*    request_body;
  int      peer_socket;
} Request_t;
