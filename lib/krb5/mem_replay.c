/*==============================================================================
 *
 * Project:     QAS 4.x
 *
 * File:        mem_replay.c
 *
 * Author(s):   Jeff Webb <jeff.webb@quest.com>
 *
 * Description: Quest's Replacement for Heimdal's replay.c which is a minimalistic
 *              file based replay cache, that is not connected to the krb5
 *              library. mem_replay.c contains a memory-based implementation
 *
 *============================================================================*/

/* Feature Test Switches */

/* System header files */

/* Local header files */
#include <krb5_locl.h>

/* Typedef, macro, enum/struct/union defintions */

struct krb5_rcache_data     /* Same as defined in replay.c */
{
    char    *name;
};

typedef struct quest_krb5_replay_item
{
    int32_t                         ctime_key;
    unsigned char                   AuthenticatorMD5[16];
    struct quest_krb5_replay_item   *next,
                                    *prev;
} quest_krb5_replay_item_t;

typedef struct quest_krb5_replay_cache
{
    struct krb5_rcache_data            cache;
    time_t                      life_span;
    quest_krb5_replay_item_t    *head;
    quest_krb5_replay_item_t    *tail;
} quest_krb5_replay_cache_t;

/* Forward function declarations */
static int
_add_item_to_rcache( quest_krb5_replay_cache_t *rc,
                     quest_krb5_replay_item_t *item )
{
    int         added = 0;
    quest_krb5_replay_item_t *cur_item = NULL;

    if( !rc || !item )
    {
        return KRB5_RC_UNKNOWN;
    }

    cur_item = rc->head;
    while( cur_item )
    {
        if( item->ctime_key > cur_item->ctime_key )
        {
            added = 1;
            item->prev = cur_item->prev;
            item->next = cur_item;
            cur_item->prev = item;
            if( item->prev )
            {
                item->prev->next = item;
            }
            else
            {
                rc->head = item;
            }
            if( item->next == NULL )
            {
                rc->tail = item;
            }
            break;
        }
        cur_item = cur_item->next;
    }
    if( !added )
    {
        /* Special case, the head of the list? */
        if( !rc->head )
        {
            rc->head = rc->tail = item;
        }
        else
        {
            /* Tail case */
            item->next = NULL;
            rc->tail->next = item;
            item->prev = rc->tail;
            rc->tail = item;
        }
    }

    return 0;
}

static int
_build_replay_item( time_t valid_st_time,
                    Authenticator *auth,
                    quest_krb5_replay_item_t **item )
{
    MD5_CTX     md5;
    size_t      sz;

    if( !auth || !item )
    {
        return KRB5_RC_UNKNOWN;
    }

    if( auth->ctime < valid_st_time )
    {
        *item = NULL;
        return 0;
    }

    *item = calloc( 1, sizeof( quest_krb5_replay_item_t) );
    if( *item == NULL )
    {
        return KRB5_RC_MALLOC;
    }
    (*item)->ctime_key = auth->ctime;
    MD5_Init( &md5 );
    if( auth->crealm )
    {
        MD5_Update( &md5, auth->crealm, strlen( auth->crealm ) );
    }
    for( sz = 0; sz < auth->cname.name_string.len; sz++ )
    {
        MD5_Update( &md5, auth->cname.name_string.val[sz],
                    strlen( auth->cname.name_string.val[sz] ) );
    }
    MD5_Update( &md5, &auth->ctime, sizeof(auth->ctime) );
    MD5_Update( &md5, &auth->cusec, sizeof(auth->cusec) );
    MD5_Final( (void *)(*item)->AuthenticatorMD5, &md5 );
    return 0;
}

static quest_krb5_replay_item_t *
_find_item_in_cache( krb5_context context,
                     quest_krb5_replay_cache_t *rc,
                     quest_krb5_replay_item_t *item )
{
    quest_krb5_replay_item_t        *cur_item;

    if( rc == NULL || item == NULL )
        return NULL;

    /* Clear out old records */
    cur_item = rc->head;
    while( cur_item )
    {
        if( memcmp( cur_item->AuthenticatorMD5,
                    item->AuthenticatorMD5,
                    sizeof( item->AuthenticatorMD5 ) ) == 0 )
        {
            return cur_item;
        }
        cur_item = cur_item->next;
    }
    return NULL;
}

static void
_remove_cache_items( time_t start_time,
                     quest_krb5_replay_cache_t *rc )
{
    int         check_time = (start_time > 0);

    if( rc )
    {
        quest_krb5_replay_item_t        *item = rc->tail,
                                        *prev = NULL;
        while( item )
        {
            prev = item->prev;
            if( !check_time || item->ctime_key < start_time )
            {
                memset( item->AuthenticatorMD5, 0, sizeof(item->AuthenticatorMD5) );
                free( item );
                if( prev )
                    prev->next = NULL;
                else
                {
                    /* empty list */
                    rc->head = rc->tail = NULL;
                }
            }
            else
            {
                rc->tail = item;
                break;
            }
            item = prev;
        }
    }

    return;
}

static void
_free_quest_replay_cache( krb5_context context,
                          quest_krb5_replay_cache_t *rc )
{
    if( rc )
    {
        if( rc->cache.name )            free( rc->cache.name );
        _remove_cache_items( 0, rc );
        memset( rc, 0, sizeof(quest_krb5_replay_cache_t) );
        free( rc );
    }
    return;
}

/* With the exception of krb5_rc_resolve_type()/krb5_rc_resolve_full(),
 * all krb5_rc functions MUST return 0 if the krb5_rcache is NULL
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_resolve( krb5_context context,
                 krb5_rcache id,
                 const char *name )
{
    if( id == NULL )
        return 0;

    if( name )
    {
        quest_krb5_replay_cache_t *ptr = (quest_krb5_replay_cache_t *) id;
        if( (ptr->cache.name = strdup( name )) == NULL )
        {
            krb5_set_error_string( context, "malloc: out of memory" );
            return KRB5_RC_MALLOC;
        }
        return 0;
    }
    return KRB5_RC_PARSE;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_resolve_type( krb5_context context,
                      krb5_rcache *id,
                      const char *type )
{
    if( !id )
        return 0;

    if( type )
    {
        quest_krb5_replay_cache_t *ptr = NULL;
        if( strcmp( type, "MEM" ) )
        {
            krb5_set_error_string( context, "replay cache type %s not supported", type );
            return KRB5_RC_TYPE_NOTFOUND;
        }

        /* Use what has already been created */
        if( context->rcache_ctx )
        {
            *id = context->rcache_ctx;
            return 0;
        }
        
        ptr = calloc( 1, sizeof(quest_krb5_replay_cache_t) );
        if( ptr == NULL )
        {
            krb5_set_error_string( context, "malloc: out of memory" );
            return KRB5_RC_MALLOC;
        }
        /* By default, set the life_span to the max_skew */
        ptr->life_span = context->max_skew;
        context->rcache_ctx = (krb5_rcache) ptr;
        *id = (krb5_rcache)ptr;
        return 0;
    }
    return KRB5_RC_TYPE_NOTFOUND;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_resolve_full( krb5_context context,
                      krb5_rcache *id,
                      const char *string_name )
{
    krb5_error_code     ret;

    if( !id )
        return 0;

    if( !string_name )
        return KRB5_RC_UNKNOWN;

    *id = NULL;

    if( strncmp( string_name, "MEM:", 4 ) )
    {
        krb5_set_error_string( context, "replay cache type %s not supported",
                               string_name );
        return KRB5_RC_TYPE_NOTFOUND;
    }

    /* Do not hard code type to be "MEM" but allow for KRB5RCACHETYPE
     * to be checked.  If type is set to none then do not init the replay cache
     * This is an additional change for bug# 345014. 
     * -- jayson.hurst@software.dell.com
     */
    if( (ret = krb5_rc_resolve_type( context, id, krb5_rc_default_type(context) )) )
    {
        return ret;
    }

    if( (ret = krb5_rc_resolve( context, *id, string_name + 4 )) )
    {
        krb5_rc_close( context, *id );
        *id = NULL;
    }
    return ret;
}

const char * KRB5_LIB_FUNCTION
krb5_rc_default_name( krb5_context context )
{
    return "MEM:default_rcache";
}

const char * KRB5_LIB_FUNCTION
krb5_rc_default_type( krb5_context context )
{
    /* If Environment variable KRB5RCACHETYPE has been set
     * use this value as the default replay cache type. This was intended to
     * allow end users the ablity to turn off the replay cache if the cache
     * type is set to none. Bug# 345014.
     * -- jayson.hurst@sowtware.dell.com
     */
    char *s;
    if ((s = getenv("KRB5RCACHETYPE")))
    {
        return s;
    }
    else
        return "MEM";
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_default( krb5_context context,
                 krb5_rcache *id )
{
    return krb5_rc_resolve_full( context, id, krb5_rc_default_name( context ) );
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_initialize( krb5_context context,
                    krb5_rcache id,
                    krb5_deltat auth_lifespan )
{
    if( id )
    {
        quest_krb5_replay_cache_t   *ptr = (quest_krb5_replay_cache_t *) id;
        if( auth_lifespan == 0 )
            auth_lifespan = context->max_skew;
        ptr->life_span = auth_lifespan;
        return 0;
    }
    else
    {
        krb5_set_error_string( context, "rcache not properly resolved" );
    }
    return KRB5_RC_UNKNOWN;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_recover( krb5_context context,
                 krb5_rcache id )
{
    /* Stubbed out */
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_destroy( krb5_context context,
                 krb5_rcache id )
{
    return krb5_rc_close( context, id );
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_close( krb5_context context,
               krb5_rcache id )
{
    if( id )
    {
        quest_krb5_replay_cache_t   *ptr = (quest_krb5_replay_cache_t *)id;
        _free_quest_replay_cache( context, ptr );
    }
    if( context->rcache_ctx )
    {
        context->rcache_ctx = NULL;
    }
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_store( krb5_context context,
               krb5_rcache id,
               krb5_donot_replay *rep )
{
    time_t                      valid_st_time = 0;
    quest_krb5_replay_item_t    *item = NULL;
    quest_krb5_replay_cache_t   *rc = NULL;

    /* just short circuit here */
    if( id == NULL )
        return 0;

    if( rep == NULL )
        return KRB5_RC_UNKNOWN;

    /* Make sure we clear out all expired records */
    krb5_rc_expunge( context, id );

    rc = (quest_krb5_replay_cache_t *)id;
    valid_st_time = time( NULL ) - rc->life_span;
    _build_replay_item( valid_st_time, rep, &item );
    if( item )
    {
        quest_krb5_replay_item_t    *match = _find_item_in_cache( context, rc, item );
        if( match )
        {
            free( item );
            krb5_clear_error_string( context );
            return KRB5_RC_REPLAY;
        }
        else
        {
            _add_item_to_rcache( rc, item );
        }
    }
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_expunge( krb5_context context,
                 krb5_rcache id )
{
    time_t                      valid_st_time = 0;
    quest_krb5_replay_cache_t   *rc = (quest_krb5_replay_cache_t *)id;

    if( id == NULL )
        return 0;

    valid_st_time = time( NULL ) - rc->life_span;
    _remove_cache_items( valid_st_time, rc );
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_rc_get_lifespan( krb5_context context,
                     krb5_rcache id,
                     krb5_deltat *auth_lifespan )
{
    quest_krb5_replay_cache_t   *rc = (quest_krb5_replay_cache_t *)id;

    if( !auth_lifespan )
        return KRB5_RC_UNKNOWN;

    if( !id )
    {
        *auth_lifespan = 0;
        return 0;
    }

    *auth_lifespan = rc->life_span;
    return 0;
}

const char * KRB5_LIB_FUNCTION
krb5_rc_get_name( krb5_context context,
                  krb5_rcache id )
{
    quest_krb5_replay_cache_t   *rc = (quest_krb5_replay_cache_t *)id;

    if( !id )
        return NULL;
    return rc->cache.name;
}

const char * KRB5_LIB_FUNCTION
krb5_rc_get_type( krb5_context context,
                  krb5_rcache id )
{
    if( !id )
        return NULL;
    return "MEM";
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_get_server_rcache( krb5_context context,
                        const krb5_data *piece,
                        krb5_rcache *id )
{
    /* Stubbed out */
    if( id )
        *id = NULL;
    return 0;
}

/*******************************************************************************
 * Unit tests defined below, and compiled based on MEMRCACHE_UNITTESTS macro
 *******************************************************************************/
#ifdef      MEMRCACHE_UNITTESTS

#define     UNITTEST_SKIPPED            77 /* make check skipped return code */
#define     IS_SKIPPED_TEST( x )        ( (x) == UNITTEST_SKIPPED ? 1 : 0 )
#define     IS_FAILED_TEST( x )         ( ((x) && !IS_SKIPPED_TEST((x)) ) )

static krb5_context         GlobalContext = NULL;

static void
run_test( int (*tfuncptr)(), int *run_ptr, int *failed_ptr )
{
    int             rc = UNITTEST_SKIPPED;

    if( tfuncptr )
        rc = tfuncptr();
    if( run_ptr )
        *run_ptr = !IS_SKIPPED_TEST( rc );
    if( failed_ptr )
        *failed_ptr = IS_FAILED_TEST( rc );

    return;
}

static int
run_build_replay_item_tests( void )
{
    int                         fail = 0,
                                rc = 0;
    Authenticator               test_auth;
    krb5_principal              princ;
    quest_krb5_replay_item_t    *item = NULL;

    /* validate tests with NULL authenticator/item */
    memset( &test_auth, 0, sizeof(test_auth) );
    fprintf( stdout, "\tValidating parameters..................." );
    if( (rc = _build_replay_item( 1, NULL, NULL )) != KRB5_RC_UNKNOWN ||
        (rc = _build_replay_item( 1, &test_auth, NULL )) != KRB5_RC_UNKNOWN ||
        (rc = _build_replay_item( 1, NULL, &item )) != KRB5_RC_UNKNOWN )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected error %d, got %d\n",
                 KRB5_RC_UNKNOWN, rc );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    krb5_get_default_realm( GlobalContext, &test_auth.crealm );
    krb5_parse_name( GlobalContext, "foo@blah.com", &princ );
    test_auth.cusec = 124235;
    test_auth.ctime = 100;
    copy_Principal( princ, (Principal *)&test_auth.cname );
    krb5_free_principal( GlobalContext, princ );

    fprintf( stdout, "\tTesting with older than skew time......." );
    _build_replay_item( 200, &test_auth, &item );
    if( item )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\titem should be NULL!\n" );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    fprintf( stdout, "\tTesting normal usage...................." );
    _build_replay_item( 50, &test_auth, &item );
    if( !item )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\titem should NOT be NULL!\n" );
        goto FINISHED;
    }
    if( item )
    {
        if( item->ctime_key != 100 )
        {
            ++fail;
            fprintf( stdout, "[FAILED]\n\t\tunexpected value in ctime_key\n" );
            goto FINISHED;
        }
        if( !memcmp( item->AuthenticatorMD5, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 15 ) )
        {
            ++fail;
            fprintf( stdout, "[FAILED]\n\t\tMD5 not generated properly\n" );
            goto FINISHED;
        }
    }
    fprintf( stdout, "[PASSED]\n" );

FINISHED:
    if( item )      free( item );
    free( test_auth.crealm );
    free_Principal( (Principal *)&test_auth.cname );
    return fail;
}

static int
run_krb5_rc_default_tests( void )
{
    int                 fail = 0,
                        rc = 0;
    krb5_rcache         loc_rcache = NULL,
                        sav_ptr = NULL;

    fprintf( stdout, "\tTesting normal case....................." );
    if( (rc = krb5_rc_default( GlobalContext, &loc_rcache )) != 0 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected success, got %d\n", rc );
        goto FINISHED;
    }
    if( GlobalContext->rcache_ctx != loc_rcache )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tloc_rcache ptr (%p) and Context ptr (%p) mismatch\n",
                 loc_rcache, GlobalContext->rcache_ctx );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    sav_ptr = loc_rcache;
    fprintf( stdout, "\tTesting second instance................." );
    if( (rc = krb5_rc_default( GlobalContext, &loc_rcache )) != 0 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tSecond instance error=%d\n", rc );
        goto FINISHED;
    }
    if( loc_rcache != sav_ptr )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tDid not return existing ptr %p, %p\n",
                 sav_ptr, loc_rcache );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

FINISHED:
    if( loc_rcache )
        krb5_rc_destroy( GlobalContext, loc_rcache );

    return fail;
}

static int
run_krb5_rc_destroy_tests( void )
{
    int                 fail = 0,
                        rc = 0;
    krb5_rcache         rcache = NULL;

    fprintf( stdout, "\tTesting uninitialized rcache case......." );
    if( (rc = krb5_rc_destroy( GlobalContext, rcache )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );
    
    krb5_rc_default( GlobalContext, &rcache );
    fprintf( stdout, "\tTesting normal usage...................." );

    if( (rc = krb5_rc_destroy( GlobalContext, rcache )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpecting 0, got %d\n", rc );
        goto FINISHED;
    }
    if( GlobalContext->rcache_ctx != NULL )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tPtr in context not cleaned up!\n" );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

FINISHED:
    if( GlobalContext->rcache_ctx )
    {
        krb5_rc_default( GlobalContext, &rcache );
        krb5_rc_destroy( GlobalContext, rcache );
    }

    return fail;
}

static  void
_build_test_auth( krb5_context context,
                  time_t ts,
                  int32_t cusec,
                  const char *pname,
                  Authenticator *auth )
{
    krb5_principal          princ;

    krb5_get_default_realm( GlobalContext, &auth->crealm );
    krb5_parse_name( GlobalContext, pname, &princ );
    auth->cusec = cusec;
    auth->ctime = ts;
    copy_Principal( princ, (Principal *)&auth->cname );
    krb5_free_principal( GlobalContext, princ );

    return;
}

static void
_build_test_item( time_t start_time,
                  time_t ts,
                  int32_t cusec,
                  const char *pname,
                  quest_krb5_replay_item_t **item )
{
    Authenticator               test_auth;

    memset( &test_auth, 0, sizeof( test_auth ) );
    _build_test_auth( GlobalContext, ts, cusec, pname, &test_auth );
    _build_replay_item( start_time, &test_auth, item );

    free( test_auth.crealm );
    free_Principal( (Principal *)&test_auth.cname );
    return;
}

static int
run_add_item_to_rcache_tests( void )
{
    int                         fail = 0,
                                rc = 0;
    krb5_rcache                 rcache = NULL;
    quest_krb5_replay_item_t    *item = NULL;
    quest_krb5_replay_cache_t   *qrc = NULL;

    fprintf( stdout, "\tTesting NULL parameters................." );
    krb5_rc_default( GlobalContext, &rcache );
    _build_test_item( 1, 100, 1234, "foo@blah.com", &item );
    qrc = (quest_krb5_replay_cache_t *)rcache;
    if( (rc = _add_item_to_rcache( NULL, NULL )) != KRB5_RC_UNKNOWN ||
        (rc = _add_item_to_rcache( qrc, NULL )) != KRB5_RC_UNKNOWN ||
        (rc = _add_item_to_rcache( NULL, item )) != KRB5_RC_UNKNOWN )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected %d, got %d\n",
                 KRB5_RC_UNKNOWN, rc );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    fprintf( stdout, "\tTesting First Element..................." );
    if( (rc = _add_item_to_rcache( qrc, item )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    if( qrc->head == NULL || memcmp( item->AuthenticatorMD5,
                                     qrc->head->AuthenticatorMD5,
                                     sizeof(item->AuthenticatorMD5) ) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tAfter first add, head md5 does not match!" );
        goto FINISHED;
    }
    if( qrc->tail != qrc->head )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tAfter first add, tail is not head!" );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );                
        
    fprintf( stdout, "\tTesting 2nd element....................." );
    item = NULL;
    _build_test_item( 1, 101, 1234, "second@foo.com", &item );
    if( (rc = _add_item_to_rcache( qrc, item )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    if( qrc->head != item ||
        qrc->tail == item )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tNot inserted where expected" );
        goto FINISHED;
    }
    if( qrc->head == qrc->tail )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tHead and tail match after 2nd insertion!" );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );                

    item = NULL;
    _build_test_item( 1, 100, 1234, "third@foo.com", &item );
    fprintf( stdout, "\tTesting 3rd element....................." );
    if( (rc = _add_item_to_rcache( qrc, item )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    if( qrc->head == item )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tAdded 3rd element at head\n" );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );
    item = NULL;

FINISHED:
    if( rcache )
        krb5_rc_destroy( GlobalContext, rcache );

    return fail;
}

static int
run_find_item_in_cache_tests( void )
{
    int                         fail = 0,
                                idx = 0;
    krb5_rcache                 rcache = NULL;
    quest_krb5_replay_cache_t   *qrc = NULL;
    quest_krb5_replay_item_t    *items[] = { NULL, NULL, NULL, NULL },
                                *match = NULL;
    time_t                      base_time = time( NULL );

    krb5_rc_default( GlobalContext, &rcache );
    qrc = (quest_krb5_replay_cache_t *)rcache;
    _build_test_item( base_time, base_time + 1, 1234, "first@foo.com", &items[0] );
    _build_test_item( base_time, base_time + 2, 1234, "second@foo.com", &items[1] );
    _build_test_item( base_time, base_time + 3, 1234, "third@foo.com", &items[2] );

    fprintf( stdout, "\tTesting NULL parameters................." );
    if( (match = _find_item_in_cache( GlobalContext, NULL, NULL )) ||
        (match = _find_item_in_cache( GlobalContext, qrc, NULL )) ||
        (match = _find_item_in_cache( GlobalContext, NULL, items[0] )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tReturned non null!\n" );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    _add_item_to_rcache( qrc, items[0] );
    _add_item_to_rcache( qrc, items[1] );
    _add_item_to_rcache( qrc, items[2] );

    for( idx = 0; idx < 3; idx++ )
    {
        fprintf( stdout, "\tFinding item #%d.........................", idx );
        if( (match = _find_item_in_cache( GlobalContext, qrc, items[idx] )) != items[idx] )
        {
            ++fail;
            fprintf( stdout, "[FAILED]\n\t\tFailed to find item #%d in cache!\n", idx );
            goto FINISHED;
        }
        fprintf( stdout, "[PASSED]\n" );
    }

FINISHED:
    if( rcache )
        krb5_rc_destroy( GlobalContext, rcache );

    return fail;
}

static int
run_krb5_rc_initialize_tests( void )
{
    int                         fail = 0,
                                rc = 0;
    krb5_rcache                 rcache = NULL;
    quest_krb5_replay_cache_t   *qrc = NULL;

    fprintf( stdout, "\tTesting without initializing............" );
    if( (rc = krb5_rc_initialize( GlobalContext, rcache, 10 )) != KRB5_RC_UNKNOWN )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected %d, got %d\n",
                 KRB5_RC_UNKNOWN, rc );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    fprintf( stdout, "\tTesting normal usage...................." );
    krb5_rc_default( GlobalContext, &rcache );
    qrc = (quest_krb5_replay_cache_t *)rcache;
    if( (rc = krb5_rc_initialize( GlobalContext, rcache, 600 )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    if( qrc->life_span != 600 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tLifespan not properly updated "
                 "after call to krb5_rc_initialize" );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

FINISHED:
    if( rcache )
        krb5_rc_destroy( GlobalContext, rcache );

    return fail;
}

static void
_free_test_auth( Authenticator *test_auth )
{
    if( test_auth->crealm )
        free( test_auth->crealm );
    free_Principal( (Principal *)&test_auth->cname );
    memset( test_auth, 0, sizeof(Authenticator) );
    return;
}

static int
_count_cache_items( quest_krb5_replay_cache_t *qrc )
{
    int             retval = 0;

    if( qrc )
    {
        quest_krb5_replay_item_t    *citem = qrc->head;
        while( citem )
        {
            ++retval;
            citem = citem->next;
        }
    }
    return retval;
}

static int
run_krb5_rc_store_tests( void )
{
    int                         fail = 0,
                                rc = 0;
    krb5_rcache                 rcache = NULL;
    quest_krb5_replay_cache_t   *qrc = NULL;
    Authenticator               test_auth;

    memset( &test_auth, 0, sizeof(test_auth) );
    krb5_rc_default( GlobalContext, &rcache );
    qrc = (quest_krb5_replay_cache_t *)rcache;
    fprintf( stdout, "\tTesting parameter validation............" );
    if( (rc = krb5_rc_store( GlobalContext, NULL, NULL )) != 0 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0 when rcache is NULL, got %d\n", rc );
        goto FINISHED;
    }
    if( (rc = krb5_rc_store( GlobalContext, rcache, NULL )) != KRB5_RC_UNKNOWN )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tReceived %d instead of %d\n",
                 rc, KRB5_RC_UNKNOWN );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    fprintf( stdout, "\tTesting calling with first object......." );
    _build_test_auth( GlobalContext, time(NULL), 123, "test_store_1@foo.com", &test_auth );
    if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    if( _count_cache_items( qrc ) != 1 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected count of 1 got %d\n",
                 _count_cache_items( qrc ) );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );
    fprintf( stdout, "\tTesting with adding duplicate..........." );
    if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) != KRB5_RC_REPLAY )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected %d, got %d\n",
                 KRB5_RC_REPLAY, rc );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );
    _free_test_auth( &test_auth );
    fprintf( stdout, "\tTesting with too old authenticator......" );
    _build_test_auth( GlobalContext, (time(NULL) - GlobalContext->max_skew - 10), 123,
                      "too_old@foo.com", &test_auth );
    if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    if( _count_cache_items( qrc ) != 1 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 1 item still, got %d\n",
                 _count_cache_items( qrc ) );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    _free_test_auth( &test_auth );
    fprintf( stdout, "\tTesting with 2nd, different auth........" );
    _build_test_auth( GlobalContext, time(NULL), 123, "test_store_2@foo.com", &test_auth );
    if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    if( _count_cache_items( qrc ) != 2 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 2 items, got %d\n",
                 _count_cache_items( qrc ) );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );
    _free_test_auth( &test_auth );
    _build_test_auth( GlobalContext, time(NULL), 1234, "test_store_2@foo.com", &test_auth );
    fprintf( stdout, "\tTesting add with different cusec value.." );
    if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
        goto FINISHED;
    }
    if( _count_cache_items( qrc ) != 3 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tExpected 3 items, got %d\n",
                 _count_cache_items( qrc ) );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );

    fprintf( stdout, "\tTrying to store same value again........" );
    if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) != KRB5_RC_REPLAY )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tDidn't detect replay\n" );
        goto FINISHED;
    }
    if( _count_cache_items( qrc ) != 3 )
    {
        ++fail;
        fprintf( stdout, "[FAILED]\n\t\tStill expected 3, got %d\n",
                 _count_cache_items( qrc ) );
        goto FINISHED;
    }
    fprintf( stdout, "[PASSED]\n" );
    _free_test_auth( &test_auth );

    {
        int         count = _count_cache_items( qrc );
        fprintf( stdout, "\tTesting with near expired object........" );
        _build_test_auth( GlobalContext,
                          time(NULL) - GlobalContext->max_skew + 3,
                          1234, "test_store_2@foo.com", &test_auth );
        if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) )
        {
            ++fail;
            fprintf( stdout, "[FAILED]\n\t\tExpected 0, got %d\n", rc );
            goto FINISHED;
        }
        if( count >= _count_cache_items( qrc ) )
        {
            ++fail;
            fprintf( stdout, "[FAILED]\n\t\tExpected count %d, got count %d\n",
                     count, _count_cache_items( qrc ) );
            goto FINISHED;
        }

        /* Store it again to get the KRB5_RC_REPLAY error */
        if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) != KRB5_RC_REPLAY )
        {
            ++fail;
            fprintf( stdout, "[FAILED]\n\t\tDid not find newly added record\n" );
            goto FINISHED;
        }
        /* Sleep for 10 seconds to make sure we expire this one */
        fprintf( stdout, "[PASSED]\n" );
        fprintf( stdout, "\tSlept 5 seconds to expire object........" );
        sleep( 5 );
        if( (rc = krb5_rc_store( GlobalContext, rcache, &test_auth )) )
        {
            ++fail;
            fprintf( stdout,
                     "[FAILED]\n\t\tExpected 0 second time around, too, got %d\n",
                     rc );
            goto FINISHED;
        }
        if( count != _count_cache_items( qrc ) )
        {
            ++fail;
            fprintf( stdout, "[FAILED]\n\t\tRecords don't appear to be expired\n" );
            goto FINISHED;
        }
        _free_test_auth( &test_auth );
        fprintf( stdout, "[PASSED]\n" );
    }

FINISHED:
    _free_test_auth( &test_auth );
    if( rcache )
        krb5_rc_destroy( GlobalContext, rcache );

    return fail;
}

int main( int argc, char **argv )
{
    int             trun = 0,
                    tfail = 0;
    
    krb5_init_context( &GlobalContext );

    fprintf( stdout, "Testing _build_replay_item()..............\n" );
    run_test( run_build_replay_item_tests, &trun, &tfail );
    fprintf( stdout, "Testing krb5_rc_default().................\n" );
    run_test( run_krb5_rc_default_tests, &trun, &tfail );
    fprintf( stdout, "Testing krb5_rc_destroy().................\n" );
    run_test( run_krb5_rc_destroy_tests, &trun, &tfail );
    fprintf( stdout, "Testing _add_item_to_rcache().............\n" );
    run_test( run_add_item_to_rcache_tests, &trun, &tfail );
    fprintf( stdout, "Testing _find_item_in_cache().............\n" );
    run_test( run_find_item_in_cache_tests, &trun, &tfail );
    fprintf( stdout, "Testing krb5_rc_initialize()..............\n" );
    run_test( run_krb5_rc_initialize_tests, &trun, &tfail );
    fprintf( stdout, "Testing krb5_rc_store()...................\n" );
    run_test( run_krb5_rc_store_tests, &trun, &tfail );

    if( GlobalContext )
        krb5_free_context( GlobalContext );

    if( trun == 0 )
        exit( UNITTEST_SKIPPED );
    exit( tfail == 0 ? EXIT_SUCCESS : EXIT_FAILURE );
}

#endif  /*  MEMRCACHE_UNITTESTS */
