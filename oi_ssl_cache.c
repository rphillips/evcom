/* This file defines a default cache mechanism for SSL sessions
 * The user may always override this by using: 
 *   gnutls_db_set_ptr, gnutls_db_set_store_function
 *   gnutls_db_set_retrieve_function, gnutls_db_set_remove_function
 */
#include <string.h> /* memcmp, memcpy */
#include <gnutls/gnutls.h>
#include "oi_ssl_cache.h" 
#include "rbtree.h"
#define OI_MAX_SESSION_KEY 32
#define OI_MAX_SESSION_VALUE 512
#ifndef MIN
# define MIN(a,b) (a < b ? a : b)
#endif

struct cache_node {
  struct rbtree_node_t node;

  gnutls_datum_t key;
  gnutls_datum_t value;

  char key_storage[OI_MAX_SESSION_KEY];
  char value_storage[OI_MAX_SESSION_VALUE];
};

static int 
cache_compare (void *left, void *right) 
{
  gnutls_datum_t *left_key = left;
  gnutls_datum_t *right_key = right;
  if(left_key->size < right_key->size)
    return -1;
  else if(left_key->size > right_key->size)
    return 1;
  else
    return memcmp( left_key->data
                 , right_key->data
                 , MIN(left_key->size, right_key->size)
                 );
}

static int
cache_store(void *data, gnutls_datum_t key, gnutls_datum_t value)
{
  rbtree tree = data;

  if( tree == NULL
   || key.size > OI_MAX_SESSION_KEY
   || value.size > OI_MAX_SESSION_VALUE
    ) return -1;

  struct cache_node *node = gnutls_malloc(sizeof(struct cache_node));

  memcpy (node->key_storage, key.data, key.size);
  node->key.size = key.size;
  node->key.data = (void*)node->key_storage;

  memcpy (node->value_storage, value.data, value.size);
  node->value.size = value.size;
  node->value.data = (void*)node->value_storage;

  node->node.key = &node->key;
  node->node.value = &node;

  rbtree_insert(tree, (rbtree_node)node);

  //printf("session_cache_store\n");

  return 0;
}

static gnutls_datum_t
cache_retrieve (void *data, gnutls_datum_t key)
{
  rbtree tree = data;
  gnutls_datum_t res = { NULL, 0 };
  struct cache_node *node = rbtree_lookup(tree, &key);

  if(node == NULL)
    return res;

  res.size = node->value.size;
  res.data = gnutls_malloc (res.size);
  if(res.data == NULL)
    return res;

  memcpy(res.data, node->value.data, res.size);

  //printf("session_cache_retrieve\n");

  return res;
}

static int
cache_remove (void *data, gnutls_datum_t key)
{
  rbtree tree = data;

  if(tree == NULL)
    return -1;

  struct cache_node *node = (struct cache_node *)rbtree_delete(tree, &key);
  if(node == NULL)
    return -1;

  gnutls_free(node);

  //printf("session_cache_remove\n");

  return 0;
}

void oi_ssl_cache_init(oi_ssl_cache *cache)
{
  rbtree_init(cache, cache_compare);
}

void oi_ssl_cache_session(oi_ssl_cache *cache, gnutls_session_t session)
{
  gnutls_db_set_ptr (session, cache);
  gnutls_db_set_store_function (session, cache_store);
  gnutls_db_set_retrieve_function (session, cache_retrieve);
  gnutls_db_set_remove_function (session, cache_remove);
}

