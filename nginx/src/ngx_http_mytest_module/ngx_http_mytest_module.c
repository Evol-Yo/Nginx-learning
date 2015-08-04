#include <unistd.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

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
	pause();
	return NGX_OK;

}

static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	//首先找到mytest配置项所属的配置块
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_mytest_handler;

	return NGX_CONF_OK;
}

