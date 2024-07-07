#include <arpa/inet.h>
#include <math.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"
#include "./sha256.h"
#include "./types.h"

// Global variables to be used by both the server and client side of the peer.
// Some of these are not currently used but should be considered STRONG hints
PeerAddress_t* my_address;

pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
PeerAddress_t** network       = NULL;
uint32_t        peer_count    = 0;

pthread_mutex_t retrieving_mutex = PTHREAD_MUTEX_INITIALIZER;
FilePath_t**    retrieving_files = NULL;
uint32_t        file_count       = 0;

pthread_mutex_t shutdown_mutex = PTHREAD_MUTEX_INITIALIZER;
ShutdownState_t shutdown_state = DONT_SHUTDOWN;

/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size,
                  int hash_size) {
  SHA256_CTX    shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i = 0; i < hash_size; i++) {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size) {
  int casc_file_size;

  FILE* fp = fopen(sourcefile, "rb");
  if (fp == 0) {
    printf("Failed to open source: %s\n", sourcefile);
    return;
  }

  fseek(fp, 0L, SEEK_END);
  casc_file_size = ftell(fp);
  fseek(fp, 0L, SEEK_SET);

  char buffer[casc_file_size];
  fread(buffer, casc_file_size, 1, fp);
  fclose(fp);

  get_data_sha(buffer, hash, casc_file_size, size);
}

/*
 * A simple min function, which apparently C doesn't have as standard
 */
uint32_t min(int a, int b) {
  if (a < b) {
    return a;
  }
  return b;
}

/*
 * Select a peer from the network at random, without picking the peer defined
 * in my_address
 */
void get_random_peer(PeerAddress_t* peer_address) {
  PeerAddress_t** potential_peers = malloc(sizeof(PeerAddress_t*));
  uint32_t        potential_count = 0;
  for (uint32_t i = 0; i < peer_count; i++) {
    if (strcmp(network[i]->ip, my_address->ip) != 0 ||
        strcmp(network[i]->port, my_address->port) != 0) {
      potential_peers                  = realloc(potential_peers,
                                                 (potential_count + 1) * sizeof(PeerAddress_t*));
      potential_peers[potential_count] = network[i];
      potential_count++;
    }
  }

  if (potential_count == 0) {
    printf("No peers to connect to. You probably have not implemented "
           "registering with the network yet.\n");
  }

  uint32_t random_peer_index = rand() % potential_count;

  memcpy(peer_address->ip, potential_peers[random_peer_index]->ip, IP_LEN);
  memcpy(peer_address->port, potential_peers[random_peer_index]->port,
         PORT_LEN);

  free(potential_peers);

  printf("Selected random peer: %s:%s\n", peer_address->ip, peer_address->port);
}

// helper functions:

bool is_fp_retrieved(char* fp) {
  pthread_mutex_lock(&retrieving_mutex);
  uint32_t i;
  for (i = 0; i < file_count; i++) {
    FilePath_t* fp_nw = retrieving_files[i];
    if (strcmp(fp, fp_nw->path) == 0) {
      pthread_mutex_unlock(&retrieving_mutex);
      return true;
    }
  }
  pthread_mutex_unlock(&retrieving_mutex);
  return false;
}

void create_request(Request_t req) {
  struct RequestHeader request_header;
  int                  payload_length = strlen(req.request_body);
  strncpy(request_header.ip, my_address->ip, IP_LEN);
  request_header.port    = htonl(atoi(my_address->port));
  request_header.command = htonl(req.command);
  request_header.length  = htonl(payload_length);

  memcpy(req.msg_buffer, &request_header, REQUEST_HEADER_LEN);
  memcpy(req.msg_buffer + REQUEST_HEADER_LEN, req.request_body, payload_length);
}

// int peer_socket = compsys_helper_open_clientfd(peer_address.ip,
// peer_address.port);
// compsys_helper_readinitb(&state, peer_socket);
void send_request(Request_t req) {
  int   fd  = req.peer_socket;
  char* buf = req.msg_buffer;
  int   n   = REQUEST_HEADER_LEN + strlen(req.request_body);
  compsys_helper_writen(fd, buf, n);
}

ShutdownState_t check_shutdown_state() {
  pthread_mutex_lock(&shutdown_mutex);
  ShutdownState_t state = shutdown_state;
  pthread_mutex_unlock(&shutdown_mutex);
  return state;
}

bool should_shutdown() { return check_shutdown_state() == SHUTDOWN; }
bool should_not_shutdown() { return !should_shutdown(); }

void do_shutdown() {
  pthread_mutex_lock(&shutdown_mutex);
  shutdown_state = SHUTDOWN;
  pthread_mutex_unlock(&shutdown_mutex);
}

FILE** output_streams[3] = {&stderr, &stdout, &stderr};
char*  output_names[3]   = {"WARNING", "INFO", "ERROR"};
void   logger(LogLevel_t level, char* format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(*output_streams[level], "{%s}: ", output_names[level]);
    vfprintf(*output_streams[level], format, args);
    fprintf(*output_streams[level], "\n");
    va_end(args);
}

// compare if the ip and port address of a peer is the same address
// as another peer
PeerComparisonResult_t peer_cmp(PeerAddress_t peer1, PeerAddress_t peer2) {
  bool ip_equal   = string_equal(peer1.ip, peer2.ip);
  bool port_equal = string_equal(peer1.port, peer2.port);

  // if the ip and port address is the same, report out PEER_EQUAL.
  if (ip_equal && port_equal)
    return PEER_EQUAL;
  // else report out PEER_NOT_EQUAL.
  else
    return PEER_NOT_EQUAL;
}

PeerExistenceStatus_t peer_exist(PeerAddress_t check_peer) {
  // we need to check if peer exists, this can be done by checkig for each
  // peer address if there is a match, if there is a match the peer already
  // exists.
  pthread_mutex_lock(&network_mutex);
  // look through all the peers in the network
  uint32_t i;
  for (i = 0; i < peer_count; i++) {
    // look at the peer index i in network is the same as the peer
    PeerAddress_t peer = *network[i];
    // nowcompare the peer address in the network index with the peer that is
    // being checked.
    PeerComparisonResult_t res = peer_cmp(check_peer, peer);
    // if the peer address is the same for the two peers being compared, then
    // return PEER_EXISTS
    if (res == PEER_EQUAL) {
      pthread_mutex_unlock(&network_mutex);
      return PEER_EXISTS;
    }
  }
  // if there is not a match, the peer does not exists
  pthread_mutex_unlock(&network_mutex);
  return PEER_NOT_EXISTS;
}

// adjust the size of the network, to make room for more peers.
AdjustResult_t peer_adjust_size(size_t new_size) {
  pthread_mutex_lock(&network_mutex);
  // Check if new size is the same size as the current size, if it is, then
  // report ADJUST_OK
  if (new_size == peer_count) {
    pthread_mutex_unlock(&network_mutex);
    return ADJUST_OK;
  }
  // if new_size is smaller than current size, then make the network size
  // smaller, by reallocating the network to a smaller size.
  PeerAddress_t** updated_network =
      realloc(network, sizeof(PeerAddress_t*) * new_size);
  // if thee network could not be reallocated, then report out ADJUST_FAIL
  if (updated_network == NULL) {
    pthread_mutex_unlock(&network_mutex);
    return ADJUST_FAIL;
  }
  // if network gets reallocated, then update the network to the new size and
  // update the peer_count to the new_size, and report out ADJUST_OK
  network    = updated_network;
  peer_count = new_size;
  pthread_mutex_unlock(&network_mutex);
  return ADJUST_OK;
}

// add a new peer to the network
PeerAppendStatus_t peer_add(PeerAddress_t* peer) {
  // add the new non exsisting peer to the network list.
  // Check if the peer is non existing, by calling peer_exist
  if (peer_exist(*peer) == PEER_EXISTS) {
    return PEER_ALREADY_EXISTS;
  }
  // change size on the network to make room for the new peer, by calling
  // peer_adjust_size.
  pthread_mutex_lock(&network_mutex);
  size_t new_size = peer_count + 1;
  pthread_mutex_unlock(&network_mutex);

  // if the network size can not be adjusted, then report out
  // PEER_APPEND_ERROR
  if (peer_adjust_size(new_size) == ADJUST_FAIL) {
    pthread_mutex_unlock(&network_mutex);
    return PEER_APPEND_ERROR;
  }
  // update network with the new peer and report out PEER_APPEND_SUCCESS
  pthread_mutex_lock(&network_mutex);
  network[new_size - 1] = peer;
  pthread_mutex_unlock(&network_mutex);
  return PEER_APPEND_SUCCESS;
}

/*
 * Send a request message to another peer on the network. Unless this is
 * specifically an 'inform' message as described in the assignment handout, a
 * reply will always be expected.
 */
void send_message(PeerAddress_t peer_address, int command, char* request_body) {
  fprintf(stdout, "Connecting to server at %s:%s to run command %d (%s)\n",
          peer_address.ip, peer_address.port, command, request_body);

  compsys_helper_state_t state;
  char                   msg_buf[MAX_MSG_LEN];
  FILE*                  fp;

  // Setup the eventual output file path. This is being done early so if
  // something does go wrong at this stage we can avoid all that pesky
  // networking

  char output_file_path[strlen(request_body) + 1];

  if (command == COMMAND_RETREIVE) {
    strcpy(output_file_path, request_body);

    if (access(output_file_path, F_OK) != 0) {
      fp = fopen(output_file_path, "a");
      fclose(fp);
    }
  }
  // Setup connection
  int peer_socket =
      compsys_helper_open_clientfd(peer_address.ip, peer_address.port);
  compsys_helper_readinitb(&state, peer_socket);

  // Construct a request message and send it to the peer
  struct RequestHeader request_header;
  strncpy(request_header.ip, my_address->ip, IP_LEN);
  request_header.port    = htonl(atoi(my_address->port));
  request_header.command = htonl(command);
  request_header.length  = htonl(strlen(request_body));

  memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
  memcpy(msg_buf + REQUEST_HEADER_LEN, request_body, strlen(request_body));
  logger(INFO, "Sending request to %s:%s", peer_address.ip, peer_address.port);

  compsys_helper_writen(peer_socket, msg_buf,
                        REQUEST_HEADER_LEN + strlen(request_body));

  // We don't expect replies to inform messages so we're done here
  if (command == COMMAND_INFORM) {
    return;
  }

  // Read a reply
  compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

  // Extract the reply header
  char reply_header[REPLY_HEADER_LEN];
  memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

  uint32_t   reply_length = ntohl(*(uint32_t*)&reply_header[0]);
  uint32_t   reply_status = ntohl(*(uint32_t*)&reply_header[4]);
  uint32_t   this_block   = ntohl(*(uint32_t*)&reply_header[8]);
  uint32_t   block_count  = ntohl(*(uint32_t*)&reply_header[12]);
  hashdata_t block_hash;
  memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
  hashdata_t total_hash;
  memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

  // Determine how many blocks we are about to recieve
  hashdata_t ref_hash;
  memcpy(ref_hash, &total_hash, SHA256_HASH_SIZE);
  uint32_t ref_count = block_count;

  // Loop until all blocks have been recieved
  for (uint32_t b = 0; b < ref_count; b++) {
    // Don't need to re-read the first block
    if (b > 0) {
      // Read the response
      compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

      // Read header
      memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

      // Parse the attributes
      reply_length = ntohl(*(uint32_t*)&reply_header[0]);
      reply_status = ntohl(*(uint32_t*)&reply_header[4]);
      this_block   = ntohl(*(uint32_t*)&reply_header[8]);
      block_count  = ntohl(*(uint32_t*)&reply_header[12]);

      memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
      memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

      // Check we're getting consistent results
      if (ref_count != block_count) {
        fprintf(stdout, "Got inconsistent block counts between blocks\n");
        close(peer_socket);
        return;
      }

      for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        if (ref_hash[i] != total_hash[i]) {
          fprintf(stdout, "Got inconsistent total hashes between blocks\n");
          close(peer_socket);
          return;
        }
      }
    }
    // Check response status
    if (reply_status != STATUS_OK) {
      if (command == COMMAND_REGISTER && reply_status == STATUS_PEER_EXISTS) {
        printf("Peer already exists\n");
      } else {
        printf("Got unexpected status %d\n", reply_status);
        close(peer_socket);
        return;
      }
    }

    // Read the payload
    char payload[reply_length + 1];
    compsys_helper_readnb(&state, msg_buf, reply_length);
    memcpy(payload, msg_buf, reply_length);
    payload[reply_length] = '\0';

    // Check the hash of the data is as expected
    hashdata_t payload_hash;
    get_data_sha(payload, payload_hash, reply_length, SHA256_HASH_SIZE);

    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
      if (payload_hash[i] != block_hash[i]) {
        fprintf(stdout, "Payload hash does not match specified\n");
        close(peer_socket);
        return;
      }
    }

    // If we're trying to get a file, actually write that file
    if (command == COMMAND_RETREIVE) {
      // Check we can access the output file
      fp = fopen(output_file_path, "r+b");
      if (fp == 0) {
        printf("Failed to open destination: %s\n", output_file_path);
        close(peer_socket);
      }

      uint32_t offset = this_block * (MAX_MSG_LEN - REPLY_HEADER_LEN);
      fprintf(stdout, "Block num: %d/%d (offset: %d)\n", this_block + 1,
              block_count, offset);
      fprintf(stdout, "Writing from %d to %d\n", offset, offset + reply_length);

      // Write data to the output file, at the appropriate place
      fseek(fp, offset, SEEK_SET);
      fputs(payload, fp);
      fclose(fp);
    }
  }

  // Confirm that our file is indeed correct
  if (command == COMMAND_RETREIVE) {
    fprintf(stdout, "Got data and wrote to %s\n", output_file_path);

    // Finally, check that the hash of all the data is as expected
    hashdata_t file_hash;
    get_file_sha(output_file_path, file_hash, SHA256_HASH_SIZE);

    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
      if (file_hash[i] != total_hash[i]) {
        fprintf(stdout, "File hash does not match specified for %s\n",
                output_file_path);
        close(peer_socket);
        return;
      }
    }
  }

  // If we are registering with the network we should note the complete
  // network reply
  char* reply_body = malloc(reply_length + 1);
  memset(reply_body, 0, reply_length + 1);
  memcpy(reply_body, msg_buf, reply_length);

  if (reply_status == STATUS_OK) {
    if (command == COMMAND_REGISTER) {
      // Your code here. This code has been added as a guide, but feel
      // free to add more, or work in other parts of the code

      // Handle the registation of a peer with the network
      handle_register(peer_socket, peer_address.ip, atoi(peer_address.port));
    }
  } else {
    printf("Got response code: %d, %s\n", reply_status, reply_body);
  }
  free(reply_body);
  close(peer_socket);
}

/*
 * Function to act as thread for all required client interactions. This thread
 * will be run concurrently with the server_thread but is finite in nature.
 *
 * This is just to register with a network, then download two files from a
 * random peer on that network. As in A3, you are allowed to use a more
 * user-friendly setup with user interaction for what files to retrieve if
 * preferred, this is merely presented as a convienient setup for meeting the
 * assignment tasks
 */
void* client_thread(void* thread_args) {
  struct PeerAddress* peer_address = thread_args;

  logger(INFO, "Client thread started");
  // Register the given user
  logger(INFO, "Registering %s:%s", peer_address->ip, peer_address->port);
  send_message(*peer_address, COMMAND_REGISTER, "\0");
  // Update peer_address with random peer from network
  logger(INFO, "Requesting random peer");
  get_random_peer(peer_address);
  // Retrieve the smaller file, that doesn't not require support for blocks
  logger(INFO, "Retrieving tiny.txt");
  send_message(*peer_address, COMMAND_RETREIVE, "tiny.txt");

  // Update peer_address with random peer from network
  logger(INFO, "Requesting random peer");
  get_random_peer(peer_address);

  // Retrieve the larger file, that requires support for blocked messages
  logger(INFO, "Retrieving hamlet.txt");
  send_message(*peer_address, COMMAND_RETREIVE, "hamlet.txt");

  return NULL;
}

void create_address(const char* ip, int port, char* new_address, size_t size) {
  snprintf(new_address, size, "%s:%d", ip, port);
}
/*
 * Handle any 'register' type requests, as defined in the asignment text. This
 * should always generate a response.
 */
void handle_register(int connfd, char* client_ip, int client_port_int) {
  // Your code here. This function has been added as a guide, but feel free
  // to add more, or work in other parts of the code.

  // check if ip is valid
  if (!is_valid_ip(client_ip) || client_ip == NULL || strlen(client_ip) == 0) {
    char msg[MAX_MSG_LEN];
    snprintf(msg, MAX_MSG_LEN, "Cannot register empty ip");
    handle_error(connfd, STATUS_BAD_REQUEST, msg);
    return;
  }

  // check if port is valid.
  char client_port_str[PORT_LEN];
  snprintf(client_port_str, sizeof(client_port_str), "%d", client_port_int);

  if (!is_valid_ip(client_ip) || client_ip == NULL || strlen(client_ip) == 0) {
    char msg[MAX_MSG_LEN];
    snprintf(msg, MAX_MSG_LEN, "Cannot register empty port");
    handle_error(connfd, STATUS_BAD_REQUEST, msg);
    return;
  }

  // generates the new address for the user with the format ip:port.
  size_t new_address_len = IP_LEN + PORT_LEN + 2;
  char*  new_address     = malloc(new_address_len);

  if (new_address == NULL) {
    perror("Failed to allocate memory");
    return;
  }

  create_address(client_ip, client_port_int, new_address, new_address_len);

  // will now handle network, so start by locking a mutex, ensureing only one
  // thread will execute the following code.
  pthread_mutex_lock(&network_mutex);

  // checking for my new address exists in the network, starts off by checking
  // if the peer with the same ip:port exists. If it exists we will handle the
  // error by returning a response that a peer exists, and unlock the mutex.
  // If the peer did not exist, we the peer will be added to the network list,
  // with the new_address values.
  PeerAddress_t* new_peer = malloc(sizeof(PeerAddress_t));
  memcpy(new_peer->ip, client_ip, IP_LEN);
  memcpy(new_peer->port, client_port_str, PORT_LEN);

  PeerAppendStatus_t res = peer_add(new_peer);
  if (res == PEER_APPEND_ERROR) {
    pthread_mutex_unlock(&network_mutex);
    char msg[MAX_MSG_LEN];
    snprintf(msg, MAX_MSG_LEN, "Failed to add peer '%s'", new_address);
    handle_error(connfd, STATUS_OTHER, msg);
    return;
  }
  if (res == PEER_ALREADY_EXISTS) {
    pthread_mutex_unlock(&network_mutex);
    char msg[MAX_MSG_LEN];
    snprintf(msg, MAX_MSG_LEN, "Cannot register peer '%s', already exists",
             new_address);
    handle_error(connfd, STATUS_PEER_EXISTS, msg);
    return;
  }

  // Then it builds a payload where each peer in the network list is added in
  // the payload, and unlock the mutex.
  size_t         payload_size = sizeof(PeerAddress_t) * peer_count;
  unsigned char* payload      = malloc(payload_size);
  if (payload == NULL) {
    // Handle memory allocation failure
    perror("Failed to allocate memory for payload");
    pthread_mutex_unlock(&network_mutex);
    return;
  }

  unsigned char* payload_ptr = payload;
  uint32_t       j;
  for (j = 0; j < peer_count; j++) {
    // Add ip and port to payload by copying the ip and port to the payload
    memcpy(payload_ptr, network[j]->ip, IP_LEN);
    payload_ptr += IP_LEN;
    memcpy(payload_ptr, network[j]->port, PORT_LEN);
    payload_ptr += PORT_LEN;
  }

  // sends a response to the registering user with the payload, payload was
  // the new network.
  // casted to char*
  build_and_send_responses(connfd, STATUS_OK, (char*)payload, payload_size);
  printf("Registered new peer %s", new_address);

  // Now we initilaize a variable, called my_address which will point to the
  // server, in which initially received the request, and we then lock the
  // network mutex, because now we are going to inform all in the network that
  // the user registered.
  pthread_mutex_lock(&network_mutex);

  // for each peer in the network, if the peer is not the server address, or
  // not the new registered user, we will construct the same payload send it
  // to each peer. using a COMMAND_INFORM, and then we release the mutex.
  uint32_t i;
  for (i = 0; i < peer_count; i++) {
    PeerAddress_t          peer     = *network[i];
    PeerComparisonResult_t cmp_res1 = peer_cmp(peer, *my_address);
    PeerComparisonResult_t cmp_res2 = peer_cmp(peer, *new_peer);
    if (cmp_res1 == PEER_NOT_EQUAL && cmp_res2 == PEER_NOT_EQUAL) {
      // Now calculate the lengtth of the message
      size_t msg_len = strlen(my_address->ip) + strlen(my_address->port) + 2;

      // Make the message to send and reallocate memory for it
      char* msg = malloc(msg_len);
      if (msg == NULL) {
        perror("Failed to allocate memory for message");
        pthread_mutex_unlock(&network_mutex);
        return;
      }

      // make the message to send
      snprintf(msg, msg_len, "%s:%s", my_address->ip, my_address->port);

      // We don't mind if this message breaks, its just a nice to
      // have update so we won't bother listening for an
      // acknowledging reply

      // set the server to the network[i] address
      PeerAddress_t* server = network[i];
      // send the message to the server wit the COMMAND_INFORM
      send_message(*server, COMMAND_INFORM, msg);

      free(msg);
      pthread_mutex_unlock(&network_mutex);
    }
    pthread_mutex_unlock(&network_mutex);
  }
}

/*
 * Handle 'inform' type message as defined by the assignment text. These will
 * never generate a response, even in the case of errors.
 */
void handle_inform(char* req, size_t req_size) {
  // Your code here. This function has been added as a guide, but feel free
  // to add more, or work in other parts of the code

  // check wether the request holds a valid IP and PORT from req_size
  if (req_size < IP_LEN + PORT_LEN) {
    logger(ERROR, "Invalid IP and PORT in inform request");
    return;
  }

  PeerAddress_t* new_peer = malloc(sizeof(PeerAddress_t));
  memcpy(new_peer->ip, req, IP_LEN);
  memcpy(new_peer->port, req + IP_LEN, PORT_LEN);

  if (!is_valid_ip(new_peer->ip)) {
    logger(ERROR, "Invalid IP address in inform request");
    free(new_peer);
    return;
  }

  if (!is_valid_port(new_peer->port)) {
    logger(ERROR, "Invalid port number in inform request");
    free(new_peer);
    return;
  }

  // create a new peer with the new ip and port
  PeerAppendStatus_t status = peer_add(new_peer);
  // TODO: maybe free memory
  if (status == PEER_ALREADY_EXISTS) {
    logger(ERROR, "Peer already exists in network");
    free(new_peer);
    return;
  }

  if (status == PEER_APPEND_ERROR) {
    logger(ERROR, "Failed to add peer to network");
    free(new_peer);
    return;
  }
}

/*
 * Handle 'retrieve' type messages as defined by the assignment text. This
 * will always generate a response
 */
void handle_retreive(int connfd, char* request, size_t payload_length) {
  // Your code here. This function has been added as a guide, but feel free
  // to add more, or work in other parts of the code
  logger(INFO, "Handling retrieve request %d", connfd);

  if (payload_length > PATH_LEN) {
    logger(ERROR, "Invalid path length in retrieve request");
    handle_error(connfd, STATUS_BAD_REQUEST,
                 "Invalid path length in retrieve request");
    return;
  }
  // char path[payload_length];
  char path[payload_length + 1];
  memcpy(path, request, payload_length);

  // FilePath_t fp = {.path = path};
  FilePath_t fp;
  // Check using access if we have permission
  if (access(fp.path, F_OK) != 0) {
    logger(ERROR, "File does not exist");
    handle_error(connfd, STATUS_BAD_REQUEST, "File does not exist");
    return;
  }
  if (is_fp_retrieved(fp.path)) {
    logger(ERROR, "File already being retrieved");
    handle_error(connfd, STATUS_BAD_REQUEST, "File already being retrieved");
    return;
  }

  // Get file data
  FILE* file = fopen(fp.path, "rb");
  if (file == NULL) {
    logger(ERROR, "Failed to open file");
    handle_error(connfd, STATUS_BAD_REQUEST, "Failed to open file");
    return;
  }
  // get file size
  fseek(file, 0L, SEEK_END);
  size_t file_size = ftell(file);
  fseek(file, 0L, SEEK_SET);

  // read file
  char* file_data = malloc(file_size);
  fread(file_data, file_size, 1, file);
  fclose(file);

  build_and_send_responses(connfd, STATUS_OK, file_data, file_size);
}

/*
 * Handler for all server requests. This will call the relevent function based
 * on the parsed command code
 */
void handle_server_request(int connfd) {
  // Your code here. This function has been added as a guide, but feel free
  // to add more, or work in other parts of the code
  logger(INFO, "Handling server request");
  RequestHeader_t req_header = {0};
  compsys_helper_readn(connfd, &req_header, sizeof(RequestHeader_t));

  uint32_t command        = ntohl(req_header.command);
  uint32_t payload_length = ntohl(req_header.length);
  uint32_t port           = ntohl(req_header.port);

  char ip[IP_LEN + 1];
  memcpy(ip, req_header.ip, IP_LEN);
  ip[IP_LEN] = '\0';
  if (!is_valid_ip(ip)) {
    logger(ERROR, "Invalid IP address");
    handle_error(connfd, STATUS_MALFORMED, "Invalid IP address");
    return;
  }

  char port_str[PORT_LEN + 1];
  snprintf(port_str, PORT_LEN, "%d", port);
  port_str[PORT_LEN] = '\0';
  if (!is_valid_port(port_str)) {
    logger(ERROR, "Invalid port number");
    handle_error(connfd, STATUS_MALFORMED, "Invalid port number");
    return;
  }

  if (payload_length <= 0 && (command != COMMAND_REGISTER)) {
    logger(ERROR, "Invalid payload length of nontype register command");
    handle_error(connfd, STATUS_MALFORMED,
                 "Invalid payload length of nontype register command");
    return;
  }

  if (command < 1 || command > 3) {
    logger(ERROR, "Invalid command");
    handle_error(connfd, STATUS_BAD_REQUEST, "Invalid command");
    return;
  }

  // if command is REGISTER there will be no payload
  char* request_body;
  if (payload_length > 0) {
    request_body = malloc(payload_length + 1);
    compsys_helper_readn(connfd, request_body, payload_length);
    request_body[payload_length] = '\0';
  }

  switch (command) {
    case COMMAND_REGISTER:
      logger(INFO, "Registering new peer");
      handle_register(connfd, ip, port);
      break;
    case COMMAND_INFORM:
      logger(INFO, "Informing network of new peer");
      handle_inform(request_body, payload_length);
      break;
    case COMMAND_RETREIVE:
      logger(INFO, "Retrieving file");
      handle_retreive(connfd, request_body, payload_length);
      break;
    default:
      // this wont ever happen, because the bounds for the command has already
      // been checked
      break;
  }
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread(void* thread_args) {
  logger(INFO, "Server thread started");
  (void)thread_args; // avoid warning
  // Your code here. This function has been added as a guide, but feel free
  // to add more, or work in other parts of the code

  // A server uses bind to ask the kernel to associate the server's socket
  // address with a socket descriptor
  // int bind(int sockfd, const struct sockaddr* my_addr, socklen_t addrlen);

  // Server calls the listen function to tell the kernel that a descriptor
  // will be used by a server rather than a client int listen(int sockfd, int
  // backlog);

  // Server wait for connection request from clients by calling accecptt
  // int accept(int listen, struct sockaddr* addr, socklen_t* addrlen);

  // compsys_helper does all of this for me
  int socket_fd = compsys_helper_open_listenfd(my_address->port);

  // on errors, it should return -2 for getaddrinfo error, -1 with errno set
  // for other errors.
  if (socket_fd <= -1) {
    logger(ERROR, "Failed to open socket");
    return NULL;
  }

  // Should then run concurrently with the client thread, in an infinte
  // nature, meaning that we can keep accepting clients
  while (should_not_shutdown()) {
    // accept a client
    int client_fd = accept(socket_fd, NULL, NULL);

    // if client_fd is -1, it is an error
    if (client_fd == -1) {
      if (should_shutdown()) {
        break;
      }
      logger(ERROR, "Failed to accept client");
      continue;
    }

    handle_server_request(client_fd);
    close(client_fd);
  }
  return NULL;
}

//
void handle_error(int connfd, int status, char msg[]) {
  // Should handle any errors that we meet during the request handling and
  // reponse process. has a status code that describes the error encountered
  // msg(str) that decriptive response with details what went wrong
  // It will print a message to the server command line, and return a response
  // to the request client.
  printf("%s\n", msg);
  build_and_send_responses(connfd, status, msg, strlen(msg));
}

void build_and_send_responses(int connfd, int status, char msg[],
                              size_t payload_size) {
  // this should build a response and send it.
  // status(int): The response status code. Should reflect the content of the
  // message itself char[] msg: The response message body. get the checksum of
  // the total message data to send now calculate how long the payload can be,
  // as there is a limit of how many bytes can be sent, and a header that must
  // be attached to each message.
  // get the checksum of the total message data to send

  // Compute the checksum of the entire message
  hashdata_t checksum;
  get_data_sha(msg, checksum, payload_size, SHA256_HASH_SIZE);

  // calculate how long the payload can be, as we have a set litmit of how
  // many bytes can be sent, ad a header that must be attatched to each
  // message.

  // Calculate how long the payload can be, accounting for the header
  size_t sendable_length = MAX_MSG_LEN - REPLY_HEADER_LEN;
  // size_t or int

  // Calculate the number of blocks needed
  // If the message is empty, set block count to 1
  int blocks_count = (int)ceil((double)strlen(msg) / sendable_length);
  if (strlen(msg) == 0) {
    blocks_count = 1;
  }

  // Allocate memory for storing the blocks
  char** blocks = malloc(blocks_count * sizeof(char*));
  if (blocks == NULL) {
    logger(ERROR, "Failed to allocate memory for blocks");
    return;
  }

  // loop through as long as there is data left
  int this_block = 0;
  while (strlen(msg) > 0) {
    size_t msg_len = strlen(msg);
    size_t block_len;
    if (msg_len < sendable_length)
      block_len = msg_len;
    else
      block_len = sendable_length;

    // Allocate memory for the block
    // take some of the data that fits within the
    // sendable length for a block
    // Allocate memory for the block
    blocks[this_block] = strndup(msg, block_len);
    if (blocks[this_block] == NULL) {
      logger(ERROR, "Failed to allocate memory for block");
      // Free already allocated blocks
      int j;
      for (j = 0; j < this_block; j++) {
        free(blocks[j]);
      }
      free(blocks);
      return;
    }

    // remove the slice of data by skipping over the
    msg += block_len;
    // increment the block number
    this_block++;
  }

  // loop through to send one or more blocks of payload
  // assemble an individual payload block
  int i;
  for (i = 0; i < blocks_count; i++) {
    char          msg_buf[MAX_MSG_LEN] = {0};
    ReplyHeader_t reply;
    size_t        block_len = strlen(blocks[i]);
    reply.length            = htonl(block_len);
    reply.status            = htonl(status);
    reply.this_block        = htonl(i);
    reply.block_count       = htonl(blocks_count);

    // Compute the hash of the current block
    hashdata_t block_hash;
    get_data_sha(blocks[i], block_hash, block_len, SHA256_HASH_SIZE);
    memcpy(reply.block_hash, block_hash, SHA256_HASH_SIZE);
    memcpy(reply.total_hash, checksum, SHA256_HASH_SIZE);

    // Copy the reply header and block data into the message buffer
    memcpy(msg_buf, &reply, REPLY_HEADER_LEN);
    memcpy(msg_buf + REPLY_HEADER_LEN, blocks[i], block_len);
    // Send or process the msg_buf as needed (this part is application-specific)
    // Example: send(msg_buf, sizeof(msg_buf));
    compsys_helper_writen(connfd, msg_buf, REPLY_HEADER_LEN + block_len);

    // Free the dynamically allocated block memory
    free(blocks[i]);
  }
  free(blocks);
}

int main(int argc, char** argv) {
  // Initialise with known junk values, so we can test if these were actually
  // present in the config or not
  struct PeerAddress peer_address;
  memset(peer_address.ip, '\0', IP_LEN);
  memset(peer_address.port, '\0', PORT_LEN);
  memcpy(peer_address.ip, "x", 1);
  memcpy(peer_address.port, "x", 1);

  // Users should call this script with a single argument describing what
  // config to use
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  my_address = (PeerAddress_t*)malloc(sizeof(PeerAddress_t));
  memset(my_address->ip, '\0', IP_LEN);
  memset(my_address->port, '\0', PORT_LEN);

  // Read in configuration options. Should include a client_ip, client_port,
  // server_ip, and server_port
  char buffer[128];
  fprintf(stderr, "Got config path at: %s\n", argv[1]);
  FILE* fp = fopen(argv[1], "r");
  while (fgets(buffer, 128, fp)) {
    if (starts_with(buffer, MY_IP)) {
      memcpy(&my_address->ip, &buffer[strlen(MY_IP)],
             strcspn(buffer, "\r\n") - strlen(MY_IP));
      if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid client IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
      }
    } else if (starts_with(buffer, MY_PORT)) {
      memcpy(&my_address->port, &buffer[strlen(MY_PORT)],
             strcspn(buffer, "\r\n") - strlen(MY_PORT));
      if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid client port: %s\n", my_address->port);
        exit(EXIT_FAILURE);
      }
    } else if (starts_with(buffer, PEER_IP)) {
      memcpy(peer_address.ip, &buffer[strlen(PEER_IP)],
             strcspn(buffer, "\r\n") - strlen(PEER_IP));
      if (!is_valid_ip(peer_address.ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", peer_address.ip);
        exit(EXIT_FAILURE);
      }
    } else if (starts_with(buffer, PEER_PORT)) {
      memcpy(peer_address.port, &buffer[strlen(PEER_PORT)],
             strcspn(buffer, "\r\n") - strlen(PEER_PORT));
      if (!is_valid_port(peer_address.port)) {
        fprintf(stderr, ">> Invalid peer port: %s\n", peer_address.port);
        exit(EXIT_FAILURE);
      }
    }
  }
  fclose(fp);

  retrieving_files = malloc(file_count * sizeof(FilePath_t*));
  srand(time(0));

  network    = malloc(sizeof(PeerAddress_t*));
  network[0] = my_address;
  peer_count = 1;

  // Setup the client and server threads
  pthread_t client_thread_id;
  pthread_t server_thread_id;
  if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x') {
    pthread_create(&client_thread_id, NULL, client_thread, &peer_address);
  }
  pthread_create(&server_thread_id, NULL, server_thread, NULL);

  // Start the threads. Note that the client is only started if a peer is
  // provided in the config. If none is we will assume this peer is the first
  // on the network and so cannot act as a client.
  if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x') {
    pthread_join(client_thread_id, NULL);
  }
  pthread_join(server_thread_id, NULL);

  exit(EXIT_SUCCESS);
}