/**
 *       @file  daemon.c
 *      @brief  Functionality of commotion-dnsproxy
 *
 *     @author  Dan Staples (dismantl), danstaples@opentechinstitute.org
 *
 * This file is part of Commotion, Copyright (c) 2013, Josh King 
 * 
 * Commotion is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published 
 * by the Free Software Foundation, either version 3 of the License, 
 * or (at your option) any later version.
 * 
 * Commotion is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Commotion.  If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#define _GNU_SOURCE
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <ldns/ldns.h>
#include <getopt.h>
#include "debug.h"

#define FAKE_IP "1.3.3.7"
#define LOOP_MAXEVENT 64
#define LISTENING_PORT 5335
#define SERVER_PORT 53
#define BUFSIZE 1024

static bool loop_exit = false;
static struct epoll_event *events = NULL;
static int poll_fd;
static int lfd;

struct dns_requester {
  int fd;
  struct sockaddr_in src;
};

// create fake A record response
static ssize_t
fake_response(ldns_pkt *orig, uint8_t **buf)
{
  ssize_t len = -1;
  
  ldns_pkt *fake = ldns_pkt_clone(orig);
  CHECK_MEM(fake);
  ldns_rdf *owner = ldns_rdf_clone(ldns_rr_list_owner(ldns_pkt_question(fake)));
  CHECK_MEM(owner);
  ldns_rr_list_deep_free(ldns_pkt_answer(fake));
  
  ldns_pkt_set_rcode(fake, LDNS_RCODE_NOERROR);
  
  ldns_rr_list *answers = ldns_rr_list_new();
  CHECK_MEM(answers);
  
  ldns_rr *answer = ldns_rr_new();
  ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
  CHECK_MEM(answer);
  
  ldns_rr_set_owner(answer, owner);
  ldns_rr_set_ttl(answer, 1);
  
  struct in_addr fake_addr;
  CHECK(inet_aton(FAKE_IP, &fake_addr) != 0, "Failed to convert fake IP address");
  ldns_rdf *answer_rd = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A, sizeof(struct in_addr), &fake_addr);
  CHECK_MEM(answer_rd);
  
  CHECK(ldns_rr_push_rdf(answer, answer_rd), "Failed to push rdf");
  CHECK(ldns_rr_list_push_rr(answers, answer), "Failed to push rr");
  ldns_pkt_set_answer(fake, answers);
  ldns_pkt_set_section_count(fake, LDNS_SECTION_ANSWER, 1);
  
  CHECK(ldns_pkt2wire(buf, fake, &len) == LDNS_STATUS_OK,
	"Failed to create fake DNS response");

error:
  if (fake)
    ldns_pkt_free(fake);
  return len;
}

static int
dispatch_request(int server_port)
{
  int ret = -1;
  struct dns_requester *client = calloc(1, sizeof(struct dns_requester));
  CHECK_MEM(client);
  
  char buf[BUFSIZE] = {0};
  socklen_t client_len = sizeof(client->src);
  int len = recvfrom(lfd, buf, sizeof(buf), 0, (struct sockaddr*)&client->src, &client_len);
  CHECK(len > 0 && len < BUFSIZE, "Failed to receive DNS request from client");
  // 	  DEBUG("Received request from %s", inet_ntoa(client->src.sin_addr));
  
  // proxy request to DNS server
  int pfd = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(pfd != -1, "Failed to create proxy socket");
  struct sockaddr_in dnsm_addr;
  dnsm_addr.sin_family = AF_INET;
  dnsm_addr.sin_port = htons(server_port);
  assert(inet_aton("127.0.0.1",&dnsm_addr.sin_addr));
  
  CHECK(sendto(pfd, buf, len, 0, &dnsm_addr, sizeof(dnsm_addr)) == len, 
	"Failed to proxy request to DNS server");
  
  client->fd = pfd;
  
  struct epoll_event event;
  memset(&event, 0, sizeof(struct epoll_event));
  event.events = EPOLLIN;
  event.data.ptr = client;
  CHECK(epoll_ctl(poll_fd, EPOLL_CTL_ADD, pfd, &event) != -1,
	"Failed to add proxy socket to epoll");
  
  ret = 0;
error:
  return ret;
}

// get response from DNS server
static int
dispatch_response(int fd, struct sockaddr_in *src)
{
  int ret = -1;
  char buf[BUFSIZE] = {0};
  uint8_t *new_buf = NULL;
  ldns_pkt *p = NULL;
  
  int len = recv(fd, buf, sizeof(buf), 0);
  CHECK(len > 0 && len < BUFSIZE, "Failed to receive DNS response from server");
  
  // convert into ldns format
  CHECK(ldns_wire2pkt(&p, buf, len) == LDNS_STATUS_OK, "Failed to parse DNS response");
  
  if (ldns_pkt_get_rcode(p) == LDNS_RCODE_REFUSED) {
    ssize_t new_size = fake_response(p, &new_buf);
    CHECK(new_size > 0, "Failed to create fake response");
    CHECK(sendto(lfd, new_buf, new_size, 0, (struct sockaddr*)src, sizeof(struct sockaddr_in)) == new_size, 
	  "Failed to proxy fake response to client");
  } else {
    // proxy response back to client
    CHECK(sendto(lfd, buf, len, 0, (struct sockaddr*)src, sizeof(struct sockaddr_in)) == len, 
	  "Failed to proxy response to client");
  }
  
  ret = 0;
error:
  if (new_buf)
    free(new_buf);
  if (p)
    ldns_pkt_free(p);
  close(fd);
  return ret;
}

static void _co_loop_handle_signals(int sig) {
  switch(sig) {
    case SIGHUP:
      DEBUG("Received SIGHUP signal.");
      break;
    case SIGINT:
    case SIGTERM:
      DEBUG("Loop exiting.");
      loop_exit = true;
      break;
    default:
      WARN("Unhandled signal %s", strsignal(sig));
      break;
  }
}

static void _setup_signals(void) {
  struct sigaction new_sigaction;
  sigset_t new_sigset;
  
  //Set signal mask - signals we want to block
  sigemptyset(&new_sigset);
  sigaddset(&new_sigset, SIGTSTP); //ignore TTY stop signals
  sigaddset(&new_sigset, SIGTTOU); //ignore TTY background writes
  sigaddset(&new_sigset, SIGTTIN); //ignore TTY background reads
  sigprocmask(SIG_BLOCK, &new_sigset, NULL); //block the above signals

  //Set up signal handler
  new_sigaction.sa_handler = _co_loop_handle_signals;
  sigemptyset(&new_sigaction.sa_mask);
  new_sigaction.sa_flags = 0;

  //Signals to handle:
  sigaction(SIGHUP, &new_sigaction, NULL); //catch hangup signal
  sigaction(SIGTERM, &new_sigaction, NULL); //catch term signal
  sigaction(SIGINT, &new_sigaction, NULL); //catch interrupt signal
}

static void
daemon_start(char *pidfile)
{
  if (getppid() == 1)
    return;
  
  int pid = fork(); /* Fork parent process */
  if (pid < 0)
    exit(EXIT_FAILURE);
  if (pid > 0) {
    printf("Child process created: %d\n", pid);
    exit(EXIT_SUCCESS); /* exit parent process */
  }
  
  umask(027);
  
#ifdef USESYSLOG
  openlog("Commotion",LOG_PID,LOG_USER); 
#endif
  
  int sid = setsid();
  
  if (sid < 0)
    exit(EXIT_FAILURE);
  
  for (int i = getdtablesize(); i >=0; --i)
    close(i);
  
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  
  if ((chdir("/")) < 0)
    exit(EXIT_FAILURE);
  
  int pid_filehandle = open(pidfile, O_RDWR|O_CREAT, 0644);
  if(pid_filehandle == -1) {
    ERROR("Could not lock PID lock file %s, exiting", pidfile);
    exit(EXIT_FAILURE);
  }
  char str[10];
  sprintf(str, "%d\n", getpid());
  write(pid_filehandle, str, strlen(str));
}

static void print_usage() {
  printf(
    "Commotion DNS Proxy\n"
    "https://commotionwireless.net\n\n"
    "Usage: dnsproxy [options]\n"
    "\n"
    "Options:\n"
    " -b, --bind <port>         Specify port to listen on.\n"
    " -s, --server-port <port>  Specify port of DNS server to connect to.\n"
    " -n, --nodaemonize         Do not fork into the background.\n"
    " -p, --pid <file>      Specify pid file.\n"
    " -h, --help                Print this usage message.\n"
  );
}

int
main(int argc, char **argv)
{
  int ret = 1,
      opt = 0,
      opt_index = 0,
      daemonize = 1,
      port = LISTENING_PORT,
      server_port = SERVER_PORT;
  char *pidfile = NULL;

  static const char *opt_string = "hnb:s:p:";
  static struct option long_opts[] = {
    {"help", no_argument, NULL, 'h'},
    {"nodaemon", no_argument, NULL, 'n'},
    {"bind", required_argument, NULL, 'b'},
    {"pid", required_argument, NULL, 'p'},
    {"server-port", required_argument, NULL, 's'}
  };
  
  /* Parse command line arguments */
  opt = getopt_long(argc, argv, opt_string, long_opts, &opt_index);
  
  while(opt != -1) {
    switch(opt) {
      case 'b':
	port = strtol(optarg, NULL, 10);
	CHECK(port > 0 && port <= 65535, "Invalid listening port");
	break;
      case 's':
	server_port = strtol(optarg, NULL, 10);
	CHECK(server_port > 0 && server_port <= 65535, "Invalid listening port");
	break;
      case 'n':
	daemonize = 0;
	break;
      case 'p':
	pidfile = optarg;
	break;
      case 'h':
      default:
	print_usage();
	return 0;
	break;
    }
    opt = getopt_long(argc, argv, opt_string, long_opts, &opt_index);
  }
  
  if(daemonize) {
    CHECK(pidfile, "Must specify PID file");
    daemon_start(pidfile);
  }
  
  struct sockaddr_in laddr = {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr = {
      .s_addr = htonl(INADDR_ANY)
    }
  };
  
  // create listening socket
  lfd = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(lfd != -1, "Failed to create listening socket");
  CHECK(bind(lfd, (struct sockaddr*)&laddr, sizeof(laddr)) != -1, "Failed to bind to socket");
  
  // setup for epoll
  CHECK((poll_fd = epoll_create1(0)) != -1, "Failed to create epoll event.");
  struct epoll_event events[LOOP_MAXEVENT];
  memset(&events, 0, LOOP_MAXEVENT * sizeof(struct epoll_event));
  
  _setup_signals();
  
  // add listening socket to epoll
  struct epoll_event event;
  memset(&event, 0, sizeof(struct epoll_event));
  event.events = EPOLLIN;
  struct dns_requester server = {
    .fd = lfd,
    .src = {0}
  };
  event.data.ptr = &server;
  CHECK(epoll_ctl(poll_fd, EPOLL_CTL_ADD, lfd, &event) != -1,
	"Failed to add listening socket to epoll");
  
  //Main event loop.
  while(!loop_exit) {
    int n = epoll_wait(poll_fd, events, LOOP_MAXEVENT, -1);
    if (loop_exit) break;
    CHECK(n != -1, "epoll_wait error");
    for(int i = 0; i < n; i++) {
      struct dns_requester *requester = (struct dns_requester*)events[i].data.ptr;
      int fd = requester->fd;
      if (events[i].events & EPOLLERR) {
	ERROR("epoll error on socket fd %d", fd);
	if (fd == lfd)
	  goto error;
	close(fd);
      } else if (events[i].events & EPOLLHUP) {
	close(fd);
      } else {
	if (fd == lfd) {
	  CHECK(dispatch_request(server_port) == 0, "Failed to dispatch request to DNS server");
	} else {
	  CHECK(dispatch_response(fd, &requester->src) == 0, "Failed to dispatch response to client");
	  free(requester);
	}
      }
    }
  }

  ret = 0;
error:
  close(lfd);
  close(poll_fd);
  return ret;
}