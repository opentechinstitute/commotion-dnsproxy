#ifndef CO_DNSPROXY_DEBUG_H
#define CO_DNSPROXY_DEBUG_H

#include <stdio.h>
#include <errno.h>
#include <string.h>

#undef LOG
#undef DEBUG
#undef CLEAN_ERRNO
#undef ERROR
#undef WARN
#undef INFO
#undef CHECK
#undef SENTINEL
#undef CHECK_MEM
#undef CHECK_DEBUG

#ifdef USESYSLOG
#include <syslog.h>
#define LOG(M, ...) syslog(M, ##__VA_ARGS__)
#else
#define LOG(M, N, ...) fprintf(stderr, "["M"] " N, ##__VA_ARGS__)
#define LOG_INFO "LOG_INFO"
#define LOG_WARNING "LOG_WARNING"
#define LOG_ERR "LOG_ERR"
#define LOG_DEBUG "LOG_DEBUG"
#endif

#if defined(NDEBUG)
#define DEBUG(M, ...)
#else
#define DEBUG(M, ...) LOG(LOG_DEBUG, "(%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define CLEAN_ERRNO() (errno == 0 ? "None" : strerror(errno))

#define ERROR(M, ...) LOG(LOG_ERR, "(%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, CLEAN_ERRNO(), ##__VA_ARGS__)

#define WARN(M, ...) LOG(LOG_WARNING, "(%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, CLEAN_ERRNO(), ##__VA_ARGS__)

#define INFO(M, ...) LOG(LOG_INFO, "(%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define CHECK(A, M, ...) do { if(!(A)) { ERROR(M, ##__VA_ARGS__); errno=0; goto error; } } while (0)

#define SENTINEL(M, ...)  { ERROR(M, ##__VA_ARGS__); errno=0; goto error; }

#define CHECK_MEM(A) CHECK((A), "Out of memory.")

#define CHECK_DEBUG(A, M, ...) do { if(!(A)) { DEBUG(M, ##__VA_ARGS__); errno=0; goto error; } } while(0)

#endif