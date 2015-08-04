#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	//用户散列表中的关键字
	ngx_str_t	servername;
	//仅为了方便区别
	ngx_int_t	seq;
} TestWildcardHashNode;

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


static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	//首先找到mytest配置项所属的配置块
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = NULL;

	//定义用于初始化散列表的结构体
	ngx_hash_init_t	hash;
	//用于预先向散列表中添加元素，这里的元素支持带通配符
	ngx_hash_keys_arrays_t ha;
	//支持带通配符的散列表
	ngx_hash_combined_t combinedHash;

	ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

	//临时内存池只是用于初始化通配符散列表，在初始化完成之后就可以销毁
	ha.temp_pool = ngx_create_pool(16384, cf->log);
	if(ha.temp_pool == NULL){
		return NGX_CONF_ERROR;
	}
	ha.pool = ha.temp_pool;

	//调用ngx_hash_keys_array_init方法来初始化ha
	if(ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK){
		return NGX_CONF_ERROR;
	}

	TestWildcardHashNode testHashNode[3];
	testHashNode[0].servername.len = ngx_strlen("*.test.com");
	testHashNode[0].servername.data = ngx_pcalloc(ha.pool, ngx_strlen("*.test.com"));
	ngx_memcpy(testHashNode[0].servername.data, "*.test.com", ngx_strlen("*.test.com"));

	testHashNode[1].servername.len = ngx_strlen("www.test.*");
	testHashNode[1].servername.data = ngx_pcalloc(ha.pool, ngx_strlen("www.test.*"));
	ngx_memcpy(testHashNode[1].servername.data, "www.test.*", ngx_strlen("www.test.*"));

	testHashNode[2].servername.len = ngx_strlen("www.test.com");
	testHashNode[2].servername.data = ngx_pcalloc(ha.pool, ngx_strlen("www.test.com"));
	ngx_memcpy(testHashNode[2].servername.data, "www.test.com", ngx_strlen("www.test.com"));

	//调用ngx_hash_add_key方法将testHashNode[3]这三个成员添加到ha中
	int i;
	for(i = 0; i < 3; i++){
		testHashNode[i].seq = i;
		ngx_hash_add_key(&ha, &testHashNode[i].servername, &testHashNode[i], NGX_HASH_WILDCARD_KEY);
	}

	//设置ngx_hash_init_t中的成员
	hash.key = ngx_hash_key_lc;	//哈希函数
	hash.max_size = 100;
	hash.bucket_size = 48;
	hash.name = "test_server_name_hash";
	hash.pool = ha.pool;

	//开始初始化第一个散列表
	if(ha.keys.nelts){
		//需要显示地把ngx_hash_init_t中的hash指针指向combinedHash中的完全匹配散列表
		//初始化完成之后，hash.hash就指向第一个散列表
		hash.hash = &combinedHash.hash;
		hash.temp_pool = NULL;

		//将keys动态数组直接传给ngx_hash_init方法即可，ngx_hash_init_t中的hash指针就是
		//初始化成功的散列表
		if(ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK){
			return NGX_CONF_ERROR;
		}
	}

	//初始化前置通配符散列表
	if(ha.dns_wc_head.nelts){
		hash.hash = NULL;
		//注意，ngx_hash_wildcard_init方法需要使用临时内存池
		hash.temp_pool = ha.temp_pool;
		if(ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts, ha.dns_wc_head.nelts) != NGX_OK){
			return NGX_CONF_ERROR;
		}
		combinedHash.wc_head = (ngx_hash_wildcard_t * )hash.hash;
	}

	//初始化后置通配符散列表
	if(ha.dns_wc_tail.nelts){
		hash.hash = NULL;
		//注意，ngx_hash_wildcard_init方法需要使用临时内存池
		hash.temp_pool = ha.temp_pool;
		if(ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts, ha.dns_wc_tail.nelts) != NGX_OK){
			return NGX_CONF_ERROR;
		}
		combinedHash.wc_tail = (ngx_hash_wildcard_t * )hash.hash;
	}

	//测试散列表是否工作正常
	//首先定义待查询的关键字
	ngx_str_t findServer;
	findServer.len = ngx_strlen("www.test.org");
	findServer.data = ngx_pcalloc(ha.pool, ngx_strlen("www.test.org"));
	ngx_memcpy(findServer.data, "www.test.org", ngx_strlen("www.test.org"));

	TestWildcardHashNode *findHashNode = ngx_hash_find_combined(&combinedHash, 
			ngx_hash_key_lc(findServer.data, findServer.len), findServer.data, findServer.len);

	printf("%s\n", findHashNode->servername.data);

	return NGX_CONF_OK;
}
