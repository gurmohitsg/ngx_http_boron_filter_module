#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ngx_string.h>

#include <libmemcached/memcached.h> 



typedef struct {
    ngx_str_t                  match;
    ngx_str_t                  value;

} ngx_http_sub_match_t;

typedef struct {
    ngx_uint_t                 min_match_len;
    ngx_uint_t                 max_match_len;

    u_char                     index[257];
    u_char                     shift[256];
} ngx_http_sub_tables_t;


typedef struct {

    ngx_http_sub_tables_t     *tables;

    ngx_hash_t                 types;

    ngx_flag_t                 once;
    ngx_flag_t                 last_modified;

    ngx_array_t               *types_keys;
    ngx_array_t               *matches;

    memcached_st              *memc;

    ngx_flag_t                set;

} ngx_http_boron_loc_conf_t;

typedef struct {

    ngx_str_t                  memcached_config;

} ngx_http_boron_srv_conf_t;


typedef struct {
    ngx_str_t                  saved;
    ngx_str_t                  looked;

    ngx_uint_t                once;   /* unsigned  once:1 */

    ngx_buf_t                 *buf;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_chain_t              **last_out;
    ngx_chain_t               *busy;
    ngx_chain_t               *free;

    ngx_str_t                 *sub;
    ngx_uint_t                 applied;

    ngx_int_t                  offset;
    ngx_uint_t                 index;

    ngx_http_sub_tables_t     *tables;
    ngx_array_t               *matches;
} ngx_http_boron_ctx_t;


static ngx_uint_t ngx_http_sub_cmp_index;


static ngx_int_t ngx_http_boron_output(ngx_http_request_t *r,
    ngx_http_boron_ctx_t *ctx);
static ngx_int_t ngx_http_boron_parse(ngx_http_request_t *r,
    ngx_http_boron_ctx_t *ctx, ngx_uint_t flush);
static ngx_int_t ngx_http_sub_match(ngx_http_boron_ctx_t *ctx, ngx_int_t start,
    ngx_str_t *m);

static char * ngx_http_memcached_config_boron_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_http_boron_create_conf(ngx_conf_t *cf);
static char *ngx_http_boron_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static void *ngx_http_boron_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_boron_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static void ngx_http_sub_init_tables(ngx_http_sub_tables_t *tables,
    ngx_http_sub_match_t *match, ngx_uint_t n);
static ngx_int_t ngx_http_sub_cmp_matches(const void *one, const void *two);
static ngx_int_t ngx_http_boron_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_strtmd5(ngx_pool_t *pool, u_char *data, size_t len, ngx_str_t *);

static 
u_char* ngx_strcat(ngx_pool_t *pool, const u_char *dest, size_t d_len, const u_char *src, size_t s_len);

static ngx_command_t  ngx_http_boron_filter_commands[] = {

    { ngx_string("boron_memcached_config"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_memcached_config_boron_filter,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_boron_srv_conf_t, memcached_config),
      NULL },


    { ngx_string("boron"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_boron_loc_conf_t, set),
      NULL },

    { ngx_string("boron_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_boron_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("boron_once"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_boron_loc_conf_t, once),
      NULL },

    { ngx_string("boron_last_modified"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_boron_loc_conf_t, last_modified),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_boron_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_boron_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_boron_create_srv_conf,        /* create server configuration */
    ngx_http_boron_merge_srv_conf,         /* merge server configuration */

    ngx_http_boron_create_conf,            /* create location configuration */
    ngx_http_boron_merge_conf              /* merge location configuration */
};


ngx_module_t  ngx_http_boron_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_boron_filter_module_ctx,       /* module context */
    ngx_http_boron_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_boron_header_filter(ngx_http_request_t *r)
{
    ngx_uint_t                  i, j, n;
    ngx_int_t                   rc;
    
    ngx_http_boron_ctx_t        *ctx;
    ngx_http_sub_match_t        pairs[1];
    ngx_http_sub_match_t        *matches;
    ngx_http_boron_loc_conf_t   *slcf;
    ngx_http_boron_srv_conf_t   *srcf;
    
    ngx_str_t                   hash_data, salt, key;

    memcached_st *memc;
    memcached_return_t m_rc;

    u_char *temp=NULL;
    
    char *return_value;
    size_t return_value_length;
    uint32_t flags;

    /*********************Defines the match to be searched*******************************/

    n = 1; // number of match strings
    pairs[0].match.data = (u_char *)"</head>"; // case senstive
    pairs[0].match.len = sizeof("</head>") - 1;

    /*************************************************************************************/



    srcf = ngx_http_get_module_srv_conf(r, ngx_http_boron_filter_module);
   
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_boron_filter_module);
    
    /* 
     *
     * boron filter is called on every request irrespective of whether it is defined
     * in NGINX config or not so do a check for the filter is on or off.
     *
     */
    if (!slcf->set)
    {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "boron: filter is off skipping current request");
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_length_n == 0
        || ngx_http_test_content_type(r, &slcf->types) == NULL)
    {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: data is not of type \'text/html\' skipping current request"); 
        return ngx_http_next_header_filter(r);
    }

     if(slcf->memc == NULL)
    {
        /* connect to memchached */
        slcf->memc = memcached((char *)srcf->memcached_config.data, srcf->memcached_config.len);
        if(slcf->memc == NULL){
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: cannot connect to memcached server");
            return ngx_http_next_header_filter(r);
        }

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: succesfully connected to memcached");
    }
    else
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: already connected to memcached");

    /* get the local copy of memcache connection */
    memc = slcf ->memc;

    /* add salt to string */
    salt.data = (u_char *)"http";
    salt.len = ngx_strlen(salt.data);

    /* generate data to be hashed */
    hash_data.data = ngx_strcat(r->pool, salt.data, salt.len, r->headers_in.server.data, r->headers_in.server.len);
    hash_data.len = ngx_strlen(hash_data.data);
    hash_data.data = ngx_strcat(r->pool, hash_data.data, hash_data.len, r->uri.data, r->uri.len);
    hash_data.len = ngx_strlen(hash_data.data);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: hashed data \"%s\"", hash_data.data);

    /* generate memcache key */
    rc = ngx_strtmd5(r->pool, hash_data.data, hash_data.len, &key);
    if(rc == NGX_ERROR){
        return rc;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: md5 key : \"%V\"", &key);

    if ((m_rc = memcached_exist(memc, (char *)key.data, key.len)) != MEMCACHED_SUCCESS)
    {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: key doesnot exist skipping current request");
        return ngx_http_next_header_filter(r);
    }
     

    return_value = memcached_get(memc, (char *)key.data, key.len, &return_value_length, &flags, &m_rc);
    if(m_rc == MEMCACHED_SUCCESS)
    {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: memcached value %s",return_value);
        temp = ngx_strcat(r->pool, (u_char *)return_value, return_value_length,(u_char *)"\n</head>",8) ;
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: string to be injected: %s",temp);
        pairs[0].value.data = (u_char *)temp;
        pairs[0].value.len = ngx_strlen(pairs[0].value.data);
        
    }
       
    
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_boron_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
 
        matches = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_match_t) * n);
        if (matches == NULL) {
            return NGX_ERROR;
        }

        j = 0;
        for (i = 0; i < n; i++) {

            matches[j].value = pairs[i].value;

            matches[j].match = pairs[i].match;
            

            j++;
        }

        if (j == 0) {
            return ngx_http_next_header_filter(r);
        }

        ctx->matches = ngx_palloc(r->pool, sizeof(ngx_array_t));
        if (ctx->matches == NULL) {
            return NGX_ERROR;
        }

        ctx->matches->elts = matches;
        ctx->matches->nelts = j;

        ctx->tables = ngx_palloc(r->pool, sizeof(ngx_http_sub_tables_t));
        if (ctx->tables == NULL) {
            return NGX_ERROR;
        }

        ngx_http_sub_init_tables(ctx->tables, ctx->matches->elts,
                                 ctx->matches->nelts);
    

    ngx_http_set_ctx(r, ctx, ngx_http_boron_filter_module);

    ctx->saved.data = ngx_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->saved.data == NULL) {
        return NGX_ERROR;
    }

    ctx->looked.data = ngx_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->looked.data == NULL) {
        return NGX_ERROR;
    }

    ctx->offset = ctx->tables->min_match_len - 1;
    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);

        if (!slcf->last_modified) {
            ngx_http_clear_last_modified(r);
            ngx_http_clear_etag(r);

        } else {
            ngx_http_weak_etag(r);
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_boron_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_str_t                 *sub;
    ngx_uint_t                 flush, last;
    ngx_chain_t               *cl;
    ngx_http_boron_ctx_t        *ctx;
    ngx_http_sub_match_t      *match;
    ngx_http_boron_loc_conf_t   *slcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_boron_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }
    

    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (ngx_http_boron_output(r, ctx) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "boron: http sub filter \"%V\"", &r->uri);

    flush = 0;
    last = 0;

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->buf->flush || ctx->buf->recycled) {
            flush = 1;
        }

        if (ctx->in == NULL) {
            last = flush;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {
            

            rc = ngx_http_boron_parse(r, ctx, last);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "boron: parse: %i, looked: \"%V\" %p-%p",
                           rc, &ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }




            if (ctx->saved.len) {


                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: saved: \"%V\"", &ctx->saved);

                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: error");
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->pos = ngx_pnalloc(r->pool, ctx->saved.len);
                if (b->pos == NULL) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: error");
                    return NGX_ERROR;
                }

                ngx_memcpy(b->pos, ctx->saved.data, ctx->saved.len);
                b->last = b->pos + ctx->saved.len;
                b->memory = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                ctx->saved.len = 0;
            }

            
            
            if (ctx->copy_start != ctx->copy_end) {

                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: eorr");
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));

                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;
                b->shadow = NULL;
                b->last_buf = 0;
                b->last_in_chain = 0;
                b->recycled = 0;

                if (b->in_file) {
                    b->file_last = b->file_pos + (b->last - ctx->buf->pos);
                    b->file_pos += b->pos - ctx->buf->pos;
                }

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }
            


            if (rc == NGX_AGAIN) {
                
                continue;
            }
            

            /* rc == NGX_OK */

            cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            slcf = ngx_http_get_module_loc_conf(r, ngx_http_boron_filter_module);


            if (ctx->sub == NULL) {
                ctx->sub = ngx_pcalloc(r->pool, sizeof(ngx_str_t)
                                                * ctx->matches->nelts);
                if (ctx->sub == NULL) {
                    return NGX_ERROR;
                }
            }

            sub = &ctx->sub[ctx->index];
            if (sub->data == NULL) {
                match = ctx->matches->elts;
                 sub->data = match[ctx->index].value.data;
                 sub->len = match[ctx->index].value.len;
            }
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: sub->data : %s sub->lenght%d", sub->data, sub->len);
            if (sub->len) {
                b->memory = 1;
                b->pos = sub->data;
                b->last = sub->data + sub->len;

            } else {
                b->sync = 1;
            }

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->index = 0;
            ctx->once = slcf->once && (++ctx->applied == ctx->matches->nelts);

            continue;
        }

        if (ctx->looked.len
            && (ctx->buf->last_buf || ctx->buf->last_in_chain))
        {
            cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->pos = ctx->looked.data;
            b->last = b->pos + ctx->looked.len;
            b->memory = 1;

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->looked.len = 0;
        }

        if (ctx->buf->last_buf || ctx->buf->flush || ctx->buf->sync
            || ngx_buf_in_memory(ctx->buf))
        {
            if (b == NULL) {
                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->sync = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->last_in_chain = ctx->buf->last_in_chain;
            b->flush = ctx->buf->flush;
            b->shadow = ctx->buf;

            b->recycled = ctx->buf->recycled;
        }

        ctx->buf = NULL;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_boron_output(r, ctx);
}


static ngx_int_t
ngx_http_boron_output(ngx_http_request_t *r, ngx_http_boron_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "boron: sub out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = ngx_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static ngx_int_t
ngx_http_boron_parse(ngx_http_request_t *r, ngx_http_boron_ctx_t *ctx,
    ngx_uint_t flush)
{
    u_char                   *p, c;
    ngx_str_t                *m;
    ngx_int_t                 offset, start, next, end, len, rc;
    ngx_uint_t                shift, i, j;
    ngx_http_sub_match_t     *match;
    ngx_http_sub_tables_t    *tables;
    ngx_http_boron_loc_conf_t  *slcf;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "boron: parser");

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_boron_filter_module);
    tables = ctx->tables;
    match = ctx->matches->elts;

    offset = ctx->offset;
    end = ctx->buf->last - ctx->pos;

    if (ctx->once) {
        /* sets start and next to end */
        offset = end + (ngx_int_t) tables->min_match_len - 1;
        goto again;
    }

    while (offset < end) {

        c = offset < 0 ? ctx->looked.data[ctx->looked.len + offset]
                       : ctx->pos[offset];

        c = ngx_tolower(c);

        shift = tables->shift[c];
        if (shift > 0) {
            offset += shift;
            continue;
        }

        /* a potential match */

        start = offset - (ngx_int_t) tables->min_match_len + 1;

        i = ngx_max(tables->index[c], ctx->index);
        j = tables->index[c + 1];

        while (i != j) {

            if (slcf->once && ctx->sub && ctx->sub[i].data) {
                goto next;
            }

            m = &match[i].match;

            rc = ngx_http_sub_match(ctx, start, m);

            if (rc == NGX_DECLINED) {
                goto next;
            }

            ctx->index = i;

            if (rc == NGX_AGAIN) {
                goto again;
            }

            ctx->offset = offset + (ngx_int_t) m->len;
            next = start + (ngx_int_t) m->len;
            end = ngx_max(next, 0);
            rc = NGX_OK;

            goto done;

        next:

            i++;
        }

        offset++;
        ctx->index = 0;
    }

    if (flush) {
        for ( ;; ) {
            start = offset - (ngx_int_t) tables->min_match_len + 1;

            if (start >= end) {
                break;
            }

            for (i = 0; i < ctx->matches->nelts; i++) {
                m = &match[i].match;

                if (ngx_http_sub_match(ctx, start, m) == NGX_AGAIN) {
                    goto again;
                }
            }

            offset++;
        }
    }

again:

    ctx->offset = offset;
    start = offset - (ngx_int_t) tables->min_match_len + 1;
    next = start;
    rc = NGX_AGAIN;

done:

    /* send [ - looked.len, start ] to client */

    ctx->saved.len = ctx->looked.len + ngx_min(start, 0);
    ngx_memcpy(ctx->saved.data, ctx->looked.data, ctx->saved.len);

    ctx->copy_start = ctx->pos;
    ctx->copy_end = ctx->pos + ngx_max(start, 0);

    /* save [ next, end ] in looked */

    len = ngx_min(next, 0);
    p = ctx->looked.data;
    p = ngx_movemem(p, p + ctx->looked.len + len, - len);

    len = ngx_max(next, 0);
    p = ngx_cpymem(p, ctx->pos + len, end - len);
    ctx->looked.len = p - ctx->looked.data;

    /* update position */

    ctx->pos += end;
    ctx->offset -= end;

    return rc;
}


static ngx_int_t
ngx_http_sub_match(ngx_http_boron_ctx_t *ctx, ngx_int_t start, ngx_str_t *m)
{
    u_char  *p, *last, *pat, *pat_end;

    pat = m->data;
    pat_end = m->data + m->len;

    if (start >= 0) {
        p = ctx->pos + start;

    } else {
        last = ctx->looked.data + ctx->looked.len;
        p = last + start;

        while (p < last && pat < pat_end) {
            if (ngx_tolower(*p) != *pat) {
                return NGX_DECLINED;
            }

            p++;
            pat++;
        }

        p = ctx->pos;
    }

    while (p < ctx->buf->last && pat < pat_end) {
        if (ngx_tolower(*p) != *pat) {
            return NGX_DECLINED;
        }

        p++;
        pat++;
    }

    if (pat != pat_end) {
        /* partial match */
        return NGX_AGAIN;
    }

    return NGX_OK;
}



static char *
ngx_http_memcached_config_boron_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_boron_srv_conf_t *srcf = conf;
    ngx_str_t                         *value;
    
    value = cf->args->elts;

    // parsing memcahced_config for it syntax
    if (value[1].len == 0 || (ngx_strstr(value[1].data, "--SERVER=") == NULL)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "memcache config not defined correctly");
        return NGX_CONF_ERROR;
    }
    
    srcf->memcached_config = value[1];
   
    return NGX_CONF_OK;

}
 

static void *
ngx_http_boron_create_conf(ngx_conf_t *cf)
{
    ngx_http_boron_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_boron_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->pairs = NULL;
     *     conf->tables = NULL;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->matches = NULL;
     */
    slcf->set = NGX_CONF_UNSET;
    slcf->once = NGX_CONF_UNSET;
    slcf->last_modified = NGX_CONF_UNSET;
    slcf->memc = NULL;

    return slcf;
}


static void *
ngx_http_boron_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_boron_srv_conf_t  *srcf;
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "created server config");
  
    srcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_boron_srv_conf_t));
    if (srcf == NULL) {
        return NULL;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "created server config");

    return srcf;
}

static char *
ngx_http_boron_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_boron_srv_conf_t  *prev = parent;
    ngx_http_boron_srv_conf_t  *conf = child;
    ngx_conf_merge_str_value(conf->memcached_config, prev->memcached_config, NULL);


    return NGX_CONF_OK;
}

static char *
ngx_http_boron_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_boron_loc_conf_t  *prev = parent;
    ngx_http_boron_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->once, prev->once, 1);
    ngx_conf_merge_value(conf->last_modified, prev->last_modified, 0);
    ngx_conf_merge_value(conf->set, prev->set, 0)
    //ngx_conf_merge_str_value(conf->memcached_config, prev->memcached_config, NULL);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "merged value");

   
    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->memc == NULL) {
        conf->matches = prev->matches;
        conf->tables = prev->tables;
        conf->memc = prev->memc;    }
 
    return NGX_CONF_OK;
}


static void
ngx_http_sub_init_tables(ngx_http_sub_tables_t *tables,
    ngx_http_sub_match_t *match, ngx_uint_t n)
{
    u_char      c;
    ngx_uint_t  i, j, min, max, ch;

    min = match[0].match.len;
    max = match[0].match.len;

    for (i = 1; i < n; i++) {
        min = ngx_min(min, match[i].match.len);
        max = ngx_max(max, match[i].match.len);
    }

    tables->min_match_len = min;
    tables->max_match_len = max;

    ngx_http_sub_cmp_index = tables->min_match_len - 1;
    ngx_sort(match, n, sizeof(ngx_http_sub_match_t), ngx_http_sub_cmp_matches);

    min = ngx_min(min, 255);
    ngx_memset(tables->shift, min, 256);

    ch = 0;

    for (i = 0; i < n; i++) {

        for (j = 0; j < min; j++) {
            c = match[i].match.data[tables->min_match_len - 1 - j];
            tables->shift[c] = ngx_min(tables->shift[c], (u_char) j);
        }

        c = match[i].match.data[tables->min_match_len - 1];
        while (ch <= c) {
            tables->index[ch++] = (u_char) i;
        }
    }

    while (ch < 257) {
        tables->index[ch++] = (u_char) n;
    }
}


static ngx_int_t
ngx_http_sub_cmp_matches(const void *one, const void *two)
{
    ngx_int_t              c1, c2;
    ngx_http_sub_match_t  *first, *second;

    first = (ngx_http_sub_match_t *) one;
    second = (ngx_http_sub_match_t *) two;

    c1 = first->match.data[ngx_http_sub_cmp_index];
    c2 = second->match.data[ngx_http_sub_cmp_index];

    return c1 - c2;
}


static ngx_int_t
ngx_http_boron_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_boron_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_boron_body_filter;

    return NGX_OK;
}

/**
 * Function to generate md5 hash for given string..
 *
 * @param pool
 *   Pointer to nginx memory pool.
 * @param data
 *   Pointer to data to be hashed.
 * @param len
 *   Length of data string.
 * @return s_len
 *   Pointer to the the md5 string.
 */
static
ngx_int_t ngx_strtmd5(ngx_pool_t *pool, u_char *data, size_t len, ngx_str_t *m)
{
    
    u_char *buff, digest[16];
    ngx_uint_t i;
    ngx_md5_t md5;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, data, len);
    ngx_md5_final(digest,&md5);

    buff = ngx_palloc(pool, 33);
    if (buff == NULL) {
        return NGX_ERROR;
    }
    for (i = 0 ; i< 16 ; i++)
    {
        snprintf((char *)&(buff[i*2]), 16*2, "%02x", (unsigned int)digest[i]);
    }
    buff[33] = '\0';

    m->data = buff;
    m->len = ngx_strlen(buff);
    return NGX_OK;
}



/**
 * Function to append two strings by allocating buffer for the new string.
 *
 * @param pool
 *   Pointer to nginx memory pool.
 * @param dest
 *   Pointer to destination strig.
 * @param src
 *   Pointer to source string to be appended.
 * @return s_len
 *   Pointer to the the new created string.
 */

static 
u_char* ngx_strcat(ngx_pool_t *pool, const u_char *dest, size_t d_len, const u_char *src, size_t s_len)
{
    u_char *buff;
    ngx_uint_t  i, j;

    buff = (u_char *)ngx_palloc(pool,  d_len + s_len + 1);
    if (buff == NULL) {
        return NULL;
    }

    for(i=0;i < d_len;i++)
        buff[i] = dest [i];
    
    for(j=0; j<s_len; i++, j++)
        buff[i] = src[j];
    buff[i] = '\0';

    return buff;
}
