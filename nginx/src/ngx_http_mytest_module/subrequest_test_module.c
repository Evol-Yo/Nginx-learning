#include <unistd.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

//请求上下文
typedef struct {
	ngx_str_t		stock[6];
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
	
	NULL,	// create location configuration
	NULL	// merge location configuration
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

//父请求的回调方法
static void mytest_post_handler(ngx_http_request_t *r)
{

   //如果没有返回200,则直接把错误码发回用户
   if(r->headers_out.status != NGX_HTTP_OK){
   	ngx_http_finalize_request(r, r->headers_out.status);
   	return;
   }

   //当前请求是父请求，直接取其上下文
   ngx_http_mytest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);

   //定义发给用户的HTTP包体内容，格式为：stock[...],Today current price: ..., volumn:...
   ngx_str_t output_format = ngx_string("stock[%V], Today current price: %V, volumn: %V");

   //计算待发送包体的长度
   int bodylen = output_format.len + myctx->stock[0].len +
   	myctx->stock[1].len + myctx->stock[4].len - 6;
   r->headers_out.content_length_n = bodylen;

   //在内存池上分配内存以保存将要发送的包体
   ngx_buf_t *b = ngx_create_temp_buf(r->pool, bodylen);
   ngx_snprintf(b->pos, bodylen, (char *)output_format.data, &myctx->stock[0],
   		&myctx->stock[1], &myctx->stock[4]);
   b->last = b->pos + bodylen;
   b->last_buf = 1;

   ngx_chain_t out;
   out.buf = b;
   out.next = NULL;
   //设置Content-Type，注意，在汉字编码方面，服务器用了GBK
   static ngx_str_t type = ngx_string("text/plain; charset=GBK");
   r->headers_out.content_type = type;
   r->headers_out.status = NGX_HTTP_OK;

   r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
   ngx_int_t ret = ngx_http_send_header(r);
   ret = ngx_http_output_filter(r, &out);

   //注意，这里发送完响应后必须手动调用ngx_http_finalize_request结束请求，因为这时
   //HTTP框架不会调用它
   ngx_http_finalize_request(r, ret);


//子请求结束时的处理方法
static ngx_int_t mytest_subrequest_post_handler(ngx_http_request_t *r,
		void *data, ngx_int_t rc)
{

	pause();

	return NGX_ERROR;
}

static ngx_int_t
ngx_http_mytest_handler(ngx_http_request_t *r)
{
	//创建HTTP上下文
	ngx_http_mytest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
	if(myctx == NULL){
		myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
		if(myctx == NULL){
			return NGX_ERROR;
		}
		//将上下文设置到原始请求r中
		ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
	}

	//ngx_http_post_subrequest_t结构体会决定子请求的回调方法
	ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
	if(psr == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	//设置子请求回调方法为mytest_subrequest_post_headler
	psr->handler = mytest_subrequest_post_handler;
	
	//将data设为myctx上下文，这样回调mytest_subrequest_post_handler时传入的data参数就是myctx*
	psr->data = myctx;

	//子请求的URI前缀是/list
	ngx_str_t sub_prefix = ngx_string("/list=");
	ngx_str_t sub_location;
	sub_location.len = sub_prefix.len + r->args.len;
	sub_location.data = ngx_palloc(r->pool, sub_location.len);
	ngx_snprintf(sub_location.data, sub_location.len, "%V%V", &sub_prefix, &r->args);

	//sr就是子请求
	ngx_http_request_t *sr;
	//调用ngx_http_subrequest创建子请求，它只会返回NGX_OK或者NGX_ERROR。返回NGX_OK时，sr
	//已经是合法的子请求。注意，这里的NGX_HTTP_SUBREQUEST_IN_MEMORY参数告诉upstream模块
	//把上游服务器的响应全部保存在子请求的sr->upstream->buffer内存缓冲中
	ngx_int_t rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr,
			NGX_HTTP_SUBREQUEST_IN_MEMORY);
	if(rc != NGX_OK){
		return NGX_ERROR;
	}

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


