#ifndef oi_ssl_cache_h
#define oi_ssl_cache_h

#include "rbtree.h"
#include <gnutls/gnutls.h>
typedef struct rbtree_t oi_ssl_cache;
void oi_ssl_cache_init(oi_ssl_cache *cache);
void oi_ssl_cache_session(oi_ssl_cache *cache, gnutls_session_t session);

#endif /* oi_ssl_cache_h */
