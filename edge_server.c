/* A simple server in the internet domain using TCP
   The port number is passed as an argument */

/*
 * TODO: Thread pool, each thread has a struct which contains event_base and dnbase,
 *      after main thread accept a connection, selected a thread and assigned
 *      its evbase and dnsbase to pxy_conn_ctx_t, then add event to ctx->evbase and dnsbase
 *      call event_use_threads() at beginning
 * */
#include "helpfnc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <errno.h>


#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <event2/event-config.h>
#include <event2/util.h>


const char* sample =
"POST /document/u/0/d/18TXk0UI5pJdEBsT9sAdHyPHCxxe7xLCyhKFAtq70TZo/save?id=18TXk0UI5pJdEBsT9sAdHyPHCxxe7xLCyhKFAtq70TZo&sid=790421622421afd6&c=1&w=1&smv=2&token=AC4w5VgGNPzUiO-KUfPoF_Xz0QmZgsyUkg%3A1488316923016 HTTP/1.1\r\n"
"Host: docs.google.com\r\n"
"Connection: keep-alive\r\n"
"Content-Length: 517\r\n"
"X-Build: kix_2017.08-Tue_RC04\r\n"
"X-Same-Domain: 1\r\n"
"Origin: https://docs.google.com\r\n"
"X-Rel-Id: 135.46b9d38.s\r\n"
"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.91 Safari/537.36\r\n"
"Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n"
"X-Chrome-UMA-Enabled: 1\r\n"
"X-Chrome-Connected: id=111122620937263590269,mode=0,enable_account_consistency=true\r\n"
"Accept: */*\r\n"
" Referer: https://docs.google.com/document/d/18TXk0UI5pJdEBsT9sAdHyPHCxxe7xLCyhKFAtq70TZo/edit\r\n"
" Accept-Encoding: gzip, deflate, br\r\n"
" Accept-Language: en-US,en;q=0.8\r\n"
" Cookie: S=documents=q8a1dgODWNpH8B8KZzECpCJ0QpVDPIKF; SID=ZAQkPVIhK5xiebypIkXSb0koKhvctoCVvoicCu-jW5oFyVxjPtnx4oVUYb0U5ZEBQRb4SA.; HSID=Atd1pSV1erZ9q2RrJ; SSID=AMCYUP1U4lfAWS2Mt; APISID=9XTYwljWtzJ-rttO/AZcj5eIB8ryu4nSgy; SAPISID=KKZAp2KqE_-dIdh3/AggcGoVZZx7AalWmU; WRITELY_SID=ZAQkPUy7ZiPLlqUIyHwhQFkYbhVwb_E1JmSzUvuWWJZbN6Mcm73K2RTpu7BJJaToIXEOXQ.; S=explorer=F3MxOn0nSxzN0Q2yGngZrUUduxinHKKB; NID=98=5UaPqIcrUwY_xycmRncTenmJ_Zld0ppWipCPNnBlC3HIRslZ6UbTFMy5f4ud8PmRddAYt90ECoiweLgS_MOl_CrhItfod4PrxPNeZ90q4wOTa77aO_zt2uRC7QlwuCrv5tU7tRxiZ7M_YGNj3aflIy6XQvZdmGTq3X8SIpXZ200mrhCtMkCiRTyiPRN4HQxo0q8JiP_TFpQ40UQ_CgGPjsqT; llbcs=3; lbcs=2\r\n\r\n" "rev=1&bundles=%5B%7B%22commands%22%3A%5B%7B%22ty%22%3A%22is%22%2C%22ibi%22%3A1%2C%22s%22%3A%22Ty%22%7D%2C%7B%22ty%22%3A%22as%22%2C%22st%22%3A%22text%22%2C%22si%22%3A1%2C%22ei%22%3A2%2C%22sm%22%3A%7B%22ts_bd_i%22%3Atrue%2C%22ts_fs_i%22%3Atrue%2C%22ts_ff_i%22%3Atrue%2C%22ts_it_i%22%3Atrue%2C%22ts_sc_i%22%3Atrue%2C%22ts_st_i%22%3Atrue%2C%22ts_tw%22%3A400%2C%22ts_un_i%22%3Atrue%2C%22ts_va_i%22%3Atrue%2C%22ts_bgc_i%22%3Atrue%2C%22ts_fgc_i%22%3Atrue%7D%7D%5D%2C%22sid%22%3A%22790421622421afd6%22%2C%22reqId%22%3A0%7D%";

typedef struct pxy_conn_desc{
    struct bufferevent *bev;
    SSL *ssl;
    unsigned int closed : 1;
}pxy_conn_desc_t;

typedef struct pxy_conn_ctx{
    struct event_base * ev_base;
    struct event *ev;
    int fd; //source file descriptor;
    pxy_conn_desc_t src;
    pxy_conn_desc_t dst;
    char* sni;
    struct evdns_base * dnsbase;
    struct sockaddr_storage addr;
    socklen_t addrlen;
}pxy_conn_ctx_t;

static
pxy_conn_ctx_t *pxy_conn_ctx_init()
{
    pxy_conn_ctx_t * ctx = malloc(sizeof(pxy_conn_ctx_t));
    if(ctx == NULL){
        perror("malloc ctx failed\n");
        exit(-1);
    }
//    ctx->ssl = NULL;
    return ctx;
}

//TODO: free unused memory
void pxy_conn_ctx_free(pxy_conn_ctx_t * ctx)
{
    /* if(ctx->ssl != NULL){
     *     SSL_shutdown(ctx->ssl);
     *     SSL_free(ctx->ssl);
     * } */
}
void error(const char *msg)
{
    perror(msg);
    exit(1);
}

void init_OpenSSL()
{
    if(!SSL_library_init())
    {
        fprintf(stderr, "** OpenSSL initialization failed! \n");
    }
    SSL_load_error_strings();
}

SSL_CTX * setup_client_ctx()
{
    SSL_CTX* ctx;
    ctx = SSL_CTX_new(SSLv23_method());
    if(ctx == NULL){
        fprintf(stderr,"SSL_CTX_new failed\n");
    }


    SSL_CTX_set_options(ctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
    SSL_CTX_set_options(ctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /*  SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /*  SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /*  SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif /*  SSL_OP_NO_TICKET */
/* #ifdef SSL_OP_NO_COMPRESSION
 *     SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
 * #endif [>  SSL_OP_NO_COMPRESSION <]
 *
 * #ifdef SSL_OP_NO_SSLv2
 * #ifdef WITH_SSLV2
 * #endif [>  WITH_SSLV2 <]
 *         SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
 * #ifdef WITH_SSLV2
 * #endif [>  WITH_SSLV2 <]
 * #endif [>  !SSL_OP_NO_SSLv2 <]
 * #ifdef SSL_OP_NO_SSLv3
 *         SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
 * #endif [>  SSL_OP_NO_SSLv3 <]
 * #ifdef SSL_OP_NO_TLSv1
 *         SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
 * #endif [>  SSL_OP_NO_TLSv1 <]
 * #ifdef SSL_OP_NO_TLSv1_1
 *     SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
 * #endif [>  SSL_OP_NO_TLSv1_1 <]
 * #ifdef SSL_OP_NO_TLSv1_2
 *     SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
 * #endif [>  SSL_OP_NO_TLSv1_2 <] */

    SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
    return ctx;
}


//TODO: Error handler
static void
pxy_bev_eventcb(struct bufferevent *bev, short events, void *arg){
    pxy_conn_ctx_t *ctx =arg;
    pxy_conn_desc_t* this = (bev == ctx->src.bev)? &ctx->src : &ctx->dst;
    pxy_conn_desc_t* other = (bev == ctx->src.bev)? &ctx->dst : &ctx->src;

    if (events & BEV_EVENT_CONNECTED){
       fprintf(stderr,"Connect to GOOGLE DOC\n");
       if(this->bev == ctx->dst.bev){
           fprintf(stderr,"write connected to client23\n");
           //
           //write(ctx->fd,"CONNECTED",9);
           /* struct evbuffer *src_out = bufferevent_get_output(ctx->src.bev);
            * evbuffer_add_printf(src_out,"CONNECTED"); */
       }else{

           fprintf(stderr,"write connected to client2\n");
       }
    }
    fprintf(stderr,"write coneected finished\n");
    return;

}


static char*  modify_payload(char * data,size_t length, size_t* o_size){
    char *p = NULL;
    char* header_end = NULL;
    size_t header_size = 0;

    p = strstr(data,"\r\n\r\n");
    p += 4;
    header_end = p;
    header_size = p - data;

    //orignial payload size
    size_t pllen = length - (p - data);
    size_t dc_o_size;

    int i = 0;
    while(i < pllen){
        fprintf(stderr,"%x ", p[i] & 0xff);
        i++;
    }

    char* pl_result = decompress_and_chunkedDecoding(p,pllen, &dc_o_size);
    fprintf(stderr,"payload %s\n", pl_result);
    //modify
    // %22s%22%3A%22: prefix of modify string
    char * content = strstr(pl_result,"%22s%22%3A%22");
    if(content != NULL){
        content += strlen("%22s%22%3A%22");
        char * c_end = strstr(content,"%22");
        size_t content_size = c_end - content;
        //change the first character to m
        content[0] = 'm';
        fprintf(stderr,"modify_payload: %s\n",pl_result);
        size_t m_cd_o_size;
        char* m_cd_payload = compress_and_chunkedEncoding(pl_result, dc_o_size,&m_cd_o_size);

        /* int i = 0;
         * while(i < m_cd_o_size){
         *     fprintf(stderr,"%x ", m_cd_payload[i] & 0xff);
         *     i++;
         * } */

        char *m_req = malloc(header_size + m_cd_o_size);
        size_t index = 0;
        memset(m_req,'\0',header_size + m_cd_o_size);
        memcpy(m_req, data, header_size);
        memcpy(m_req + header_size, m_cd_payload, m_cd_o_size);

        fprintf(stderr,"modified request %s\n",m_req);
        *o_size = header_size + m_cd_o_size;
        free(pl_result);
        free(m_cd_payload);
        return m_req;
    }

    free(pl_result);

    return NULL;
}

//TODO: adapted to our own protocol
static void
pxy_bev_readcb(struct bufferevent *bev, void *arg){
    //read
    fprintf(stderr,"readcb");
    pxy_conn_ctx_t *ctx = arg;
    pxy_conn_desc_t *other = (bev == ctx->src.bev) ? &ctx->dst : &ctx->src;

    struct evbuffer *inbuf = bufferevent_get_input(bev);
    struct evbuffer *outbuf = bufferevent_get_output(other->bev);
    size_t length = evbuffer_get_length(inbuf) + 1;
    char* data = malloc(length);
    memset(data,'\0',length);
    evbuffer_copyout(inbuf,data,length-1);

    if(bev == ctx->src.bev){
        fprintf(stderr,"src data %s\n",data);
        if((strstr(data,"POST /document/save?"))){
            size_t o_size;
            char* m_result = modify_payload(data,length,&o_size);
            int i = 0;
            if(m_result != NULL){
                fprintf(stderr,"data to send %lu %s\n", o_size, m_result);
                evbuffer_add(outbuf,m_result,o_size);
                evbuffer_drain (inbuf, length-1);
                goto leave;
            }
        }
        /* evbuffer_drain(inbuf,length - 1);
         * evbuffer_add(outbuf,m_result,o_size); */
    }else{
        fprintf(stderr,"dst data %s\n",data);
    }
    evbuffer_add_buffer(outbuf,inbuf);

leave:
    if(evbuffer_get_length(outbuf) >= 1024*1024){
        bufferevent_setwatermark(other->bev,EV_WRITE,1024*1024/2, 1024*1024);
        bufferevent_disable(bev,EV_READ);
    }
}
static void
pxy_bev_writecb(struct bufferevent *bev, void *arg){
    //
    pxy_conn_ctx_t *ctx = arg;
    pxy_conn_desc_t *other = (bev == ctx->src.bev) ? &ctx->dst : &ctx->src;
    struct evbuffer *outbuf = bufferevent_get_output(bev);
    if(evbuffer_get_length(outbuf) > 0){
        bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
        bufferevent_enable(other->bev, EV_READ);
    }
}

//set bufferevent source side is non-ssl
static struct bufferevent *
pxy_bufferevent_setup(pxy_conn_ctx_t *ctx, evutil_socket_t fd, SSL *ssl){
    struct bufferevent *bev;
    if(ssl){
        fprintf(stderr,"bufferevent_openssl_socket_new\n");
        bev = bufferevent_openssl_socket_new(ctx->ev_base,fd,ssl,BUFFEREVENT_SSL_CONNECTING,BEV_OPT_DEFER_CALLBACKS);
    }else{
        //src
        bev = bufferevent_socket_new(ctx->ev_base,fd,BEV_OPT_DEFER_CALLBACKS);
    }
    bufferevent_setcb(bev,pxy_bev_readcb,pxy_bev_writecb,pxy_bev_eventcb,ctx);
    bufferevent_enable(bev,EV_READ|EV_WRITE);
    return bev;
}


// set up source side bev(non-ssl) and server side bev(ssl), connect to server
void connect_to_googledocs(int errcode, struct evutil_addrinfo* ai,void* arg)
{
    fprintf(stderr,"errcode %d\n",errcode);
    pxy_conn_ctx_t *ctx = arg;

    ctx->src.bev = pxy_bufferevent_setup(ctx,ctx->fd,NULL);
    fprintf(stderr,"after ctx->src.bev setup\n");
    assert(ai != NULL);
    memcpy(&ctx->addr,ai->ai_addr,ai->ai_addrlen);
    fprintf(stderr,"after memcpy\n");
    ctx->addrlen = ai->ai_addrlen;
    //setup server connection
    SSL_CTX * sslctx;
    // Why it doesn't work if deleting SSL_library_init() statement
    init_OpenSSL();
    SSL_library_init();
    //int error;
    //    seed_prng();
    fprintf(stderr,"before setup client ctx\n");
    sslctx = setup_client_ctx();
    fprintf(stderr,"after setup client ctx\n");
    ctx->dst.ssl = SSL_new(sslctx);
    SSL_CTX_free(sslctx);
    fprintf(stderr,"befer setup dst ctx\n");
    ctx->dst.bev = pxy_bufferevent_setup(ctx,-1,ctx->dst.ssl);
    fprintf(stderr,"after setup dst buffer\n");

/*     struct sockaddr_in serv_addr;
 *     serv_addr.sin_family = AF_INET;
 * //    serv_addr.sin_addr.s_addr = INADDR_ANY;
 *     serv_addr.sin_port = htons(443);
 *     inet_pton(AF_INET,"149.125.72.196",&serv_addr.sin_addr); */
    fprintf(stderr,"socket_connect\n");
    bufferevent_socket_connect(ctx->dst.bev,(struct sockaddr *) &ctx->addr,ctx->addrlen);
    return ;
}

struct fd_wrap{
    evutil_socket_t fd;
};

//create pxy_conn_ctx_t* ctx, read sni from client, call evdns_getaddrinfo to search
void* search_sni(void * arg)
{
//    char sniport[6];
    pxy_conn_ctx_t * ctx = pxy_conn_ctx_init();
    ctx->fd = ((struct fd_wrap *)arg)->fd;
    struct evutil_addrinfo hints;
    char* buff = malloc(100);
    memset(buff,'\0',100);

    // TODO: make it efficient, create a event and add to ..
    int n = 0;
    do{
        n = read(ctx->fd, buff,100);
    }while( n < 0);

    fprintf(stderr,"read %s\n",buff);

    if(n > 0){
        ctx->sni = buff;
//        write(ctx->fd,"CONNECTED",9);
        fprintf(stderr,"write, %s\n",ctx->sni);
    }else{
        fprintf(stderr,"can not read sni %s\n",strerror(errno));
        free(buff);
        return NULL;
    }
    memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    ctx->ev_base = event_base_new();
    ctx->dnsbase = evdns_base_new(ctx->ev_base,1);
    fprintf(stderr,"evdns_getaddrinfo\n");
    evdns_getaddrinfo(ctx->dnsbase, ctx->sni/* "docs.google.com"*/,"443",&hints, connect_to_googledocs,ctx);
    event_base_dispatch(ctx->ev_base);
    return NULL;
}

//create a new thread, fd as a parameter, search_sni function will be called
void edge_listener_acceptcb(struct evconnlistener *listener, evutil_socket_t fd,
                            struct sockaddr *peeraddr, int peeraddrlen,
                            void *arg){
    fprintf(stderr,"accept\n");
    /* char* buff = malloc(100);
     * memset(buff,'\0',100);
     * int n = 0;
     * n = read(fd, buff,100);
     * fprintf(stderr,"read %s\n",buff);
     * if(n > 0){
     *     ctx->sni = buff;
     *     write(fd,"CONNECTED",9);
     *     fprintf(stderr,"write\n");
     * }else{
     *     fprintf(stderr,"can not read sni %s\n",strerror(errno));
     *     free(buff);
     *     return;
     * } */
//    ctx->fd = fd;
    pthread_t th;
    struct fd_wrap* fw  = malloc(sizeof(struct fd_wrap));
    fw->fd = fd;
    pthread_create(&th, NULL,search_sni,fw);
//    connect_to_googledocs(ctx);
}

// setup listener, when accept a new connection, edge_listener_acceptcb function will be called
struct evconnlistener* edge_listener_setup(struct event_base *evbase)
{
    evutil_socket_t fd;
    int rv;
    int on = 1;
    fd = socket(AF_INET, SOCK_STREAM,0);
    if(fd == -1){
        error("create socket failed\n");
        evutil_closesocket(fd);
    }
    rv = evutil_make_socket_nonblocking(fd);
    if(fd == -1){
        error("set socket non-block failed\n");
        evutil_closesocket(fd);
    }

    rv = setsockopt(fd, SOL_SOCKET,SO_KEEPALIVE,(void*)&on, sizeof(on));
    if(fd == -1){
        fprintf(stderr,"set socket opt failed %s\n",strerror(errno));
        evutil_closesocket(fd);
        return NULL;
    }
//    rv = evutil_make_listen_socket_reusable(fd);
    if(fd == -1){
        fprintf(stderr,"set socket reusable failed %s\n",strerror(errno));
        evutil_closesocket(fd);
        return NULL;
    }

    struct sockaddr_in serv_addr, cli_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(1234);
    rv = bind(fd,(struct sockaddr *) &serv_addr,sizeof(struct sockaddr));

    if(rv == -1){
        fprintf(stderr,"bind socket failed %s\n",strerror(errno));
        evutil_closesocket(fd);
        return NULL;
    }

    fprintf(stderr,"evconnlistener_new\n");
    struct evconnlistener* evcl = evconnlistener_new(evbase,edge_listener_acceptcb, NULL,LEV_OPT_CLOSE_ON_FREE,1024,fd);
    fprintf(stderr,"evconnlistener_new 2\n");

    if(evcl == NULL){
        error("evconnlistener_new failed \n");
        evutil_closesocket(fd);
        return NULL;
    }
    return evcl;
}

//Connect to google doc.
//

int send_request(SSL *ssl, char * data, size_t length)
{
    int err;
    //char* sample = "sfsdf";
    err = SSL_write(ssl,data,length);
    fprintf(stderr,"after ssl_write %d\n",err);
    if(err < 0 ){
         perror("Error write request error\n");
         return 0;
     }
    char buff[10000] = {'\0'};
    int n = 0;
    do{
        n = SSL_read(ssl, buff + n, 10000);
        fprintf(stderr,"response %s\n", buff);
    }while(n > 0);
    return 1;
}



int main()
{
    /* fprintf(stderr,"start connecting to google docs\n");
     * connect_to_googledocs();
     * fprintf(stderr,"finish connecting to google docs\n"); */
    struct event_base *evbase = event_base_new();
    edge_listener_setup(evbase);
    event_base_dispatch(evbase);
    return 1;
}
