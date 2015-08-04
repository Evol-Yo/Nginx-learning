#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r);
static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);

//每个请求都会有独立的ngx_http_upstream_conf_t结构体，处于简单考虑，在mytest模块的例子
//中，所有的请求都将共享一个ngx_http_upstream_conf_t结构体，因此，这里把他放在
//ngx_http_mytest_conf_t配置结构体中
typedef struct {
	ngx_http_upstream_conf_t	upstream;
} ngx_http_mytest_conf_t;


//typedef struct {
//
//	ngx_uint_t	code;
//	ngx_uint_t	count;
//	u_char		*start;
//	u_char		*end;
//
//} ngx_mytest_http_status_t;

//上下文
typedef struct {
	ngx_http_status_t	status;
} ngx_http_mytest_ctx_t;

static ngx_command_t ngx_http_mytest_conmmands[] = {
	{
		ngx_string("mytest"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
		ngx_http_mytest,	//在出现mytest配置项后的解析方法由ngx_http_mytest“担当”
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},

	ngx_null_command
};


static ngx_http_module_t ngx_http_mytest_module_ctx = {
	NULL,	// preconfiguration
	NULL,	// postconfiguration

	NULL,	// create main configuration
	NULL,	// init main configuration


	NULL,	// create server cnofiguration
	NULL,	// merge server configuration
	
	ngx_http_mytest_create_loc_conf,	// create location configuration
	ngx_http_mytest_merge_loc_conf		// merge location configuration
};

ngx_module_t ngx_http_mytest_module = {
	NGX_MODULE_V1,					
	&ngx_http_mytest_module_ctx,	// module context
	ngx_http_mytest_conmmands, 		// module directives
    NGX_HTTP_MODULE,                // module type
	NULL,							// init master
	NULL,							// init module
	NULL,							// init process
	NULL,							// init thread
	NULL,							// exit thread
	NULL,							// exit process
	NULL,							// exit master
	NGX_MODULE_V1_PADDING
};


static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mytest_conf_t *mycf;

	mycf = (ngx_http_mytest_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_conf_t));
	if(mycf == NULL){
		return NULL;
	}

	//以下简单的硬编码ngx_http_upstream_conf_t结构中的各成员，如超时时间，都设为1分钟，这也是
	//HTTP反向代理模块的默认值
	mycf->upstream.connect_timeout = 60000;
	mycf->upstream.send_timeout = 60000;
	mycf->upstream.read_timeout = 60000;
	mycf->upstream.store_access = 0600;

	//实际上，buffering已经决定了将以固定大小的内存作为缓冲区来转发上游的响应包体，这块固定缓冲区
	//的大小就是buffer_size。如果buffering为1，就会使用更多的内存缓存来存储发往下游的响应。例如：
	//最多使用bufs。num个缓冲区且每个缓冲区大小为bufs.size。另外，还会使用临时文件，临时文件的
	//最大长度为max_temp_file_size
	mycf->upstream.buffering = 1;
	mycf->upstream.bufs.num = 8;
	mycf->upstream.bufs.size = ngx_pagesize;
	mycf->upstream.buffer_size = ngx_pagesize;
	mycf->upstream.busy_buffers_size = 2 * ngx_pagesize;
	mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;
	mycf->upstream.max_temp_file_size = 1024 * 1024 * 1024;

	//upstream模块要求hide_headers成员必须要初始化（upstream在解析完上游服务器返回的包头时，会
	//调用ngx_http_upstream_process_headers方法按照hide_headers成员将本应转发给下游的一些HTTP
	//头部隐藏）,这里将他赋为NGX_CONF_UNSET_PTR,这是为了在merge合并配置项方法中使用upstream模块
	//提供的ngx_http_upstream_hide_headers_hash方法初始化hide_headers成员
	mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
	mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

	return mycf;
}

static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),

    ngx_null_string
};

static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_mytest_conf_t *prev = (ngx_http_mytest_conf_t *)parent;
	ngx_http_mytest_conf_t *conf = (ngx_http_mytest_conf_t *)child;

	ngx_hash_init_t hash;
	hash.max_size = 100;
	hash.bucket_size = 1024;
	hash.name = "proxy_headers_hash";

	//初始化hide_headers成员
	if(ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
				&prev->upstream, ngx_http_proxy_hide_headers, &hash) != NGX_OK)
	{
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

//用于创建发送给上游服务器的HTTP请求，upstream将会回调它
static ngx_int_t
mytest_upstream_create_request(ngx_http_request_t *r)
{
	//发往google上游服务器的请求
	static ngx_str_t backendQueryLine = ngx_string(
			"GET /search?q=%V HTTP/1.1\r\nHost: cn.bing.com\r\nConnection: close\r\n\r\n");

	ngx_int_t queryLineLen = backendQueryLine.len + r->args.len-2;

	//必须在内存池中申请内存，这有以下两点好处：一个好处是，在网络状况不佳的情况下，向上游服务器
	//发送请求时，可能需要epoll多次调度send才能发送完成，这时必须保证这段内存不会得到释放；另一个
	//好处是，在请求结束时，这段内存会被自动释放，降低内存泄露的可能
	ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
	if(b == NULL)
	{
		return NGX_ERROR;
	}
	b->last = b->pos + queryLineLen;

	ngx_snprintf(b->pos, queryLineLen, (char *)backendQueryLine.data, &r->args);

	//r->upstream->request_bufs是一个ngx_chain_t结构，它包含着要发送给上游服务器的请求
	r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
	if(r->upstream->request_bufs == NULL)
	{
		return NGX_ERROR;
	}

	//request_bufs在这里之包含一个ngx_buf_t缓冲区
	r->upstream->request_bufs->buf = b;
	r->upstream->request_bufs->next = NULL;

	r->upstream->request_sent = 0;
	r->upstream->header_sent = 0;

	//header_hash不可以取0
	r->header_hash = 1;
	return NGX_OK;
}

//解析HTTP响应行
static ngx_int_t
mytest_process_status_line(ngx_http_request_t *r)
{
	size_t		len;
	ngx_int_t	rc;
	ngx_http_upstream_t	*u;

	//上下文中才会保存多次解析HTTP响应行的状态，下面首先取出请求的上下文
	ngx_http_mytest_ctx_t * ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
	if(ctx == NULL){
		return NGX_ERROR;
	}

	u = r->upstream;

	//HTTP框架提供的ngx_http_parse_status_line方法可以解析HTTP响应行，它的输入就是收到
	//的字符流和上下文中的ngx_http_status_t结构
	rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
	
	//返回NGX_AGAIN时，表示还没有解析出完整的HTTP响应行，需要接收更多的字符流在进行解析
	if(rc == NGX_AGAIN){
		return rc;
	}

	//返回NGX_ERROR时，表示没有接收到合法的HTTP响应行
	if(rc == NGX_ERROR){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"upstream sent no valid HTTP/1.0 header");

		r->http_version = NGX_HTTP_VERSION_9;
		u->state->status = NGX_HTTP_OK;
		return NGX_OK;
	}

	//以下表示在解析到完整的HTTP响应行时，会做一些简单的赋值操作，将解析出的信息设置到
	//r->upstream->headers_in结构体中。当upstream解析完所有的包头时，会把headers_in中的
	//成员设置到将要向下游发送的r->headers_out结构体中，也就是说，现在用户向headers_in中
	//设置的信息，最终都会发往下游客户端。为什么不直接设置r->headers_out而要多次一举呢？
	//因为upstream希望能够按照ngx_http_upstream_conf_t配置结构体中的hide_headers等成员对
	//发往下游的响应头部做统一处理
	if(u->state){
		u->state->status = ctx->status.code;
	}

	u->headers_in.status_n = ctx->status.code;
	
	len = ctx->status.end - ctx->status.start;
	u->headers_in.status_line.len = len;
	
	u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
	if(u->headers_in.status_line.data == NULL){
		return NGX_ERROR;
	}

	ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

	//下一步将开始解析HTTP头部。设置process_header回调方法为mytest_upstream_process_header，
	//之后在再收到的新字符流将由mytest_upstream_process_header操作
	u->process_header = mytest_upstream_process_header;

	return mytest_upstream_process_header(r);

}

//mytest_upstream_process_header方法可以解析HTTP响应头部，而这里只是简单的
//把上游服务器发送的HTTP头部添加到了请求r->upstream->headers_in.headers链表
//中。
static ngx_int_t
mytest_upstream_process_header(ngx_http_request_t *r)
{
	ngx_int_t					rc;
	ngx_table_elt_t				*h;
	ngx_http_upstream_header_t	*hh;
	ngx_http_upstream_main_conf_t	*umcf;

	//这里将upstream模块配置项ngx_http_upstream_main_conf_t取出来，对将要转发给
	//下游客户端的HTTP响应头部进行统一处理
	umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

	//循环的解析所有的HTTP头部
	for(;;){
		//HTTP框架提供了基础性的ngx_http_parse_header_line方法，它用于解析HTTP头部
		rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
		//返回NGX_OK时，表示解析出一行HTTP头部
		if(rc == NGX_OK){

			//向headers_in.headers这个ngx_list_t链表中添加HTTP头部
			h = ngx_list_push(&r->upstream->headers_in.headers);
			if(h == NULL){
				return NGX_ERROR;
			}
			//下面开始构造刚刚添加到headers链表中的HTTP头部
			h->hash = r->header_hash;
			h->key.len = r->header_name_end - r->header_name_start;
			h->value.len = r->header_end - r->header_start;
			//必须在内存池中非配存放HTTP头部的内存空间
			h->key.data = ngx_pnalloc(r->pool, 
					h->key.len + 1 + h->value.len + 1 + h->key.len);
			if(h->key.data == NULL){
				return NGX_ERROR;
			}

			h->value.data = h->key.data + h->key.len + 1;
			h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

			ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
			h->value.data[h->value.len] = '\0';
			ngx_memcpy(h->value.data, r->header_start, h->value.len);
			h->value.data[h->value.len] = '\0';

			if(h->key.len == r->lowcase_index){
				ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
			} else {
				ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
			}

			//upstream模块会对一些HTTP头部作特殊处理
			hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);

			if(hh && hh->handler(r, h, hh->offset) != NGX_OK){
				return NGX_ERROR;
			}
			continue;
		}

		//返回NGX_HTTP_PARSE_HEADER_DONE时，表示响应中的所有的HTTP头部都解析完毕，接下来
		//在接收到的都将是HTTP包体
		if(rc == NGX_HTTP_PARSE_HEADER_DONE) {
			//如果之前解析HTTP头部时没有发现server和date头部，那么下面会根据HTTP协议
			//规范添加这两个头部
			if(r->upstream->headers_in.server == NULL){
				h = ngx_list_push(&r->upstream->headers_in.headers);
				if(h == NULL){
					return NGX_ERROR;
				}
				h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s', 'e'),
									'r'), 'v'), 'e'), 'r');
				ngx_str_set(&h->key, "Server");
				ngx_str_null(&h->value);
				h->lowcase_key = (u_char *)"server";
			}

			if(r->upstream->headers_in.date == NULL){
				h = ngx_list_push(&r->upstream->headers_in.headers);
				if(h == NULL){
					return NGX_ERROR;
				}

				h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

				ngx_str_set(&h->key, "Date");
				ngx_str_null(&h->value);
				h->lowcase_key = (u_char *)"date";
			}

			return NGX_OK;
		}

		//如果返回NGX_AGAIN,则表示状态机还没有解析到完整的HTTP头部，此时要求upstream模块
		//继续接收新的字符流，然后交由process_header回调方法解析
		if(rc == NGX_AGAIN){
			return NGX_AGAIN;
		}

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"upstream sent invalid header");

		return NGX_HTTP_UPSTREAM_INVALID_HEADER; //当mytest_upstream_process_header返回NGX_OK后
												 //upstream模块开始把上游的包体直接转发到下游客户端
	}
}

//在请求结束时，将会调用finalize_request方法，由于我们没有任何需要释放的资源，所以该方法没有完成
//任何实际工作，只是因为upstream模块要求必须实现finalize_request回调方法
static void
mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"mytest_upstream_finalize_request");
}

//在ngx_http_mytest_handler方法中启动upstream
static ngx_int_t
ngx_http_mytest_handler(ngx_http_request_t *r)
{
	//首先建立HTTP上下文结构体
	ngx_http_mytest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
	if(myctx == NULL){
		myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
		if(myctx == NULL){
			return NGX_ERROR;
		}
		//将新建的上下文与请求联系起来
		ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
	}

	//对每一个要使用upstream的请求，必须调用且只能调用一次ngx_http_upstream_create方法，
	//它会初始化r->upstream成员
	if(ngx_http_upstream_create(r) != NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_upstream_create() failed");
		return NGX_ERROR;
	}


	//得到配置结构体ngx_http_mytest_conf_t
	ngx_http_mytest_conf_t *mycf = (ngx_http_mytest_conf_t *)
		ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
	ngx_http_upstream_t *u = r->upstream;

	//这里用配置文件中的结构体来赋值给r->upstream->conf成员
	u->conf = &mycf->upstream;
	
	u->buffering = mycf->upstream.buffering;
	//以下代码开始初始化resolved结构体，用来保存上游服务器的地址

	u->resolved = (ngx_http_upstream_resolved_t *)ngx_pcalloc(r->pool, 
			sizeof(ngx_http_upstream_resolved_t));
	
	if(u->resolved == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_pcalloc resolved error. %s.", strerror(errno));
		return NGX_ERROR;
	}

	//这里的上游服务器是www.bing.com
	static struct sockaddr_in backendSockAddr;
	struct hostent *pHost = gethostbyname((char*)"bing.com");
	if(pHost == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"gethostbyname fail. %s.", strerror(errno));
		return NGX_ERROR;
	}

	//访问上游服务器的80端口
	backendSockAddr.sin_family = AF_INET;
	backendSockAddr.sin_port = htons((in_port_t)80);
	char *pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));
	backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
	//myctx->backendServer.data = (u_char*)pDmsIP;
	//myctx->backendServer.len = strlen(pDmsIP);

	//将地址设置到resolved成员中
	u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
	u->resolved->socklen = sizeof(struct sockaddr_in);
	u->resolved->naddrs = 1;

	//设置三个必须实现的回调方法
	u->create_request = mytest_upstream_create_request;
	u->process_header = mytest_process_status_line;
	u->finalize_request = mytest_upstream_finalize_request;

	//这里必须将count成员加1
	r->main->count++;
	//启动upstream
	ngx_http_upstream_init(r);
	//必须返回NGX_DONE
	return NGX_DONE;

}

static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	//首先找到mytest配置项所属的配置块
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_mytest_handler;

	return NGX_CONF_OK;
}
