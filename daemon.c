#define _GNU_SOURCE
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <ldns/ldns.h>
#include "debug.h"

#define FAKE_IP "1.3.3.7"
#define LOOP_MAXEVENT 64
#define LISTENING_PORT 53
#define DNSMASQ_PORT 5335
#define BUFSIZE 1024

static bool loop_exit = false;
static struct epoll_event *events = NULL;

struct dns_requester {
  int fd;
  struct sockaddr_in src;
};

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

int
main(int argc, char **argv)
{
  int ret = 1;
  struct sockaddr_in laddr = {
    .sin_family = AF_INET,
    .sin_port = htons(LISTENING_PORT),
    .sin_addr = {
      .s_addr = htonl(INADDR_ANY)
    }
  };
  
  // TODO command line arguments
  
  // create listening socket
  int lfd = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(lfd != -1, "Failed to create listening socket");
  CHECK(bind(lfd, (struct sockaddr*)&laddr, sizeof(laddr)) != -1, "Failed to bind to socket");
  
  // setup for epoll
  int poll_fd;
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
	  struct dns_requester *client = calloc(1, sizeof(struct dns_requester));
	  CHECK_MEM(client);
	  
	  char buf[BUFSIZE] = {0};
	  socklen_t client_len = sizeof(client->src);
	  int len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&client->src, &client_len);
	  CHECK(len > 0 && len < BUFSIZE, "Failed to receive DNS request from client");
// 	  DEBUG("Received request from %s", inet_ntoa(client->src.sin_addr));
	  
	  // proxy request to DNSMasq
	  int pfd = socket(AF_INET, SOCK_DGRAM, 0);
	  CHECK(pfd != -1, "Failed to create proxy socket");
	  struct sockaddr_in dnsm_addr;
	  dnsm_addr.sin_family = AF_INET;
	  dnsm_addr.sin_port = htons(DNSMASQ_PORT);
	  assert(inet_aton("127.0.0.1",&dnsm_addr.sin_addr));
	  
	  CHECK(sendto(pfd, buf, len, 0, &dnsm_addr, sizeof(dnsm_addr)) == len, 
		"Failed to proxy request to DNS server");
	  
	  client->fd = pfd;
	  
	  event.data.ptr = client;
	  CHECK(epoll_ctl(poll_fd, EPOLL_CTL_ADD, pfd, &event) != -1,
		"Failed to add proxy socket to epoll");
	} else {
	  // get response from DNS server
	  char buf[BUFSIZE] = {0};
	  int len = recv(fd, buf, sizeof(buf), 0);
	  CHECK(len > 0 && len < BUFSIZE, "Failed to receive DNS response from server");
	  
	  // convert into ldns format
	  ldns_pkt *p = NULL;
	  CHECK(ldns_wire2pkt(&p, buf, len) == LDNS_STATUS_OK, "Failed to parse DNS response");
	  
	  if (ldns_pkt_get_rcode(p) == LDNS_RCODE_REFUSED) {
	    // send fake A response
	    ldns_pkt *fake = ldns_pkt_clone(p);
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
	    
	    uint8_t *new_buf = NULL;
	    size_t new_size;
	    CHECK(ldns_pkt2wire(&new_buf, fake, &new_size) == LDNS_STATUS_OK,
		  "Failed to create fake DNS response");
	    
	    CHECK(sendto(lfd, new_buf, new_size, 0, (struct sockaddr*)&requester->src, sizeof(requester->src)) == new_size, 
		  "Failed to proxy fake response to client");
	    
	    free(new_buf);
	    ldns_pkt_free(fake);
	  } else {
	    // proxy response back to client
	    CHECK(sendto(lfd, buf, len, 0, (struct sockaddr*)&requester->src, sizeof(requester->src)) == len, 
		  "Failed to proxy response to client");
	  }
	  
	  ldns_pkt_free(p);
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