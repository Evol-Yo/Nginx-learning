#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

//存储配置项参数
typedef struct {
	ngx_str_t		my_str;
	ngx_int_t		my_num;
	ngx_flag_t		my_flag;
	size_t			my_size;
	ngx_array_t*	my_str_array;
	ngx_array_t*	my_keyval;
	off_t			my_off;
	ngx_msec_t		my_msec;
	time_t			my_sec;
	ngx_bufs_t		my_bufs;
	ngx_uint_t		my_enum_seq;
	ngx_uint_t		my_bitmask;
	ngx_uint_t		my_access;
	ngx_path_t*		my_path;
}ngx_http_mytest_conf_t;

//ngx_http_module_t中create_loc_conf方法实现
static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mytest_conf_t *mycf;
	mycf = (ngx_http_mytest_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_conf_t));
	if(mycf == NULL){
		return NULL;
	}

	mycf->my_flag = NGX_CONF_UNSET;
	mycf->my_num  = NGX_CONF_UNSET;
	mycf->my_str_array = NGX_CONF_UNSET_PTR;
	mycf->my_keyval = NGX_CONF_UNSET;
	mycf->my_off  = NGX_CONF_UNSET;
	mycf->my_msec = NGX_CONF_UNSET_MSEC;
	mycf->my_sec  = NGX_CONF_UNSET;
	mycf->test_size = NGX_CONF_UNSET_SIZE;

	return mycf;
}

static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

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
	NULL,	// merge location configuration
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

//HTTP框架在NGX_HTTP_CONTENT_PHASE阶段调用该函数
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)
{
	//必须是GET或者HEAD方法，否则返回405
	if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))){
		return NGX_HTTP_NOT_ALLOWED;
	}

	//丢弃请求中的包体
	ngx_int_t rc = ngx_http_discard_request_body(r);
	if(rc != NGX_OK){
		return rc;
	}

	//设置返回的Content_type。注意：ngx_str_t有一个很方便的初始化宏ngx_string，它可以把ngx_str_t
	//的data和len成员都设置好
	ngx_str_t type = ngx_string("text/plain");
	//返回包体的内容
	ngx_str_t response = ngx_string("Hello World!");
	//设置返回状态码
	r->headers_out.status = NGX_HTTP_OK;
	//设置Content_length长度
	r->headers_out.content_length_n = response.len;
	//设置Content_type
	r->headers_out.content_type = type;

	//发送HTTP头部
	rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		return rc;
	}
	
	//构造ngx_buf_t结构体准备发送包体
	ngx_buf_t *b;
	b = ngx_create_temp_buf(r->pool, response.len);
	if(b == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	//将Hello World复制到ngx_buf_t指向的内存中
	ngx_memcpy(b->pos, response.data, response.len);
	//注意一定要设置好last指针
	b->last = b->pos + response.len;
	//声明这是最后一块缓冲区
	b->last_buf = 1;

	//构造发送时的ngx_chain_t结构体
	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;

	//发送包体，发送结束后HTTP框架会调用ngx_http_finalize_request方法结束请求
	return ngx_http_output_filter(r, &out);

}

static ngx_int_t ngx_http_mytest_upstream_handler(ngx_http_request_t *r)
{
	//........
	
	r->main->count++;
	ngx_http_upstream_init(r);
	return NGX_DONE;
}

static ngx_int_t ngx_http_mytest_file_handler(ngx_http_request_t *r) 
{
	//必须是GET或者HEAD方法，否则返回405
	if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))){
		return NGX_HTTP_NOT_ALLOWED;
	}

	//丢弃请求中的包体
	ngx_int_t rc = ngx_http_discard_requst_body(r);
	if(rc != NGX_OK){
		retrn rc;
	}


	//构造ngx_buf_t结构体准备发送包体
	ngx_buf_t *b;
	b = ngx_palloc(r->pool, sizeof(ngx_buf_t));

	u_char *filename = (uchar*)"/tmp/test.txt";
	b->in_file = 1;
	b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
	b->file->fd = ngx_open_file(filename, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);
	b->file->log = r->connection->log;
	b->file->name.data = filename;
	b->file->name.len = sizeof(filename) - 1;
	if(b->file->fd <= 0){
		return NGX_HTTP_NOT_FOUND;
	}

	if(ngx_file_info(filename, &b->file->info) == NGX_FILE_ERROR){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->file->info.st_size;
	b->file_pos = 0;
	b->file_last = b->file->info.st_size;
	b->last_buf = 1;

	//设置多线程下载和断点续传（range协议）
	r->allow_ranges = 1;

	//发送HTTP头部
	rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		return rc;
	}

	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;
	
	//发送包体，发送结束后HTTP框架会调用ngx_http_finalize_request方法结束请求
	return ngx_http_output_filter(r, &out);
}

static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	//首先找到mytest配置项所属的配置块
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_mytest_handler;

	return NGX_CONF_OK;
}

