
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void             *value;	//用户自定义元素的指针
    u_short           len;		//元素关键字的长度
    u_char            name[1];	//元素关键字的首地址
} ngx_hash_elt_t;


typedef struct {
    ngx_hash_elt_t  **buckets;	//指向散列表的首地址，也是第一个槽的地址
    ngx_uint_t        size;		//散列表中槽的总数
} ngx_hash_t;


typedef struct {
	//基本散列表
    ngx_hash_t        hash;		
	//当使用ngx_hash_wildcard_t通配符散列表作为某容器的元素时，可以使用这个value指向用户数据
    void             *value;
} ngx_hash_wildcard_t;

//用于初始化散列表
typedef struct {
    ngx_str_t         key;		//元素关键字
    ngx_uint_t        key_hash;	//由散列方法算出来的关键码
    void             *value;	//指向实际的用户数据
} ngx_hash_key_t;


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);


typedef struct {
	//用于精确匹配的hash表
    ngx_hash_t            hash;
	//用于查询前置通配符的hash表
    ngx_hash_wildcard_t  *wc_head;
	//用于查询后置通配符的hash表d
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t;

//用于初始化支持通配符的散列表
typedef struct {
	//指向普通的完全匹配散列表
    ngx_hash_t       *hash;
	//用于初始化预添加元素的散列方法
    ngx_hash_key_pt   key;

	//散列表中槽的最大数目
    ngx_uint_t        max_size;
	//散列表中一个槽的空间大小，它限制了每个散列元素关键字的最大长度
    ngx_uint_t        bucket_size;

	//散列表名称
    char             *name;
	//内存池
    ngx_pool_t       *pool;
	//临时内存池，它仅存在于初始化散列表之前
    ngx_pool_t       *temp_pool;
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


//负责构造ngx_hash_key_t结构
typedef struct {
	//下面的keys_hash、dns_wc_head_hash、dns_wc_tail_hash都是简易散列表，而hsize指明了
	//散列表的槽个数，其简易散列方法也需要对hsize求余
    ngx_uint_t        hsize;

	//内存池
    ngx_pool_t       *pool;
    ngx_pool_t       *temp_pool;

	//用动态数组以ngx_hash_key_t结构体保存着不含有通配符关键字的元素
    ngx_array_t       keys;
	//一个极其简易的散列表，它以数组形式保存着hsize个元素，每个元素都是ngx_array_t动态
	//数组，在用户添加元素过程中，会根据关键码将用户的ngx_str_t类型的关键字添加到ngx_array_t
	//动态数组中。这里所有用户元素的关键字都不带通配符，表示精确匹配
    ngx_array_t      *keys_hash;

	//同上，不过这里所有的用户元素的关键字都带前置通配符
    ngx_array_t       dns_wc_head;
    ngx_array_t      *dns_wc_head_hash;

	//同上，不过这里所有的用户元素的关键字都带后置通配符
    ngx_array_t       dns_wc_tail;
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t;


typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
//查找前置通配符的元素
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
//查找后值通配符的元素
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

//初始化基本的散列表
ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
//初始化通配符散列表（前置或者后置）
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)

//使用BKDR算法将任意字符串映射为整形
ngx_uint_t ngx_hash_key(u_char *data, size_t len);				
//将字符串转换为小写，再使用BKDR算法将字符串映射为整形
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);			
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


//初始化ngx_hash_keys_arrays_t结构体
//@return -- NGX_OK,表示成功；NGX_ERROR,表示失败
ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);

//向ha中添加1个元素
//	@ha -- 要初始化的ngx_hash_keys_arrays_t结构体指针
//	@key -- 添加元素的关键字
//	@value -- key关键字对应的用户数据的指针
//	@flags -- 取值有三种：NGX_HASH_WILDCARD_KEY(表示需要处理通配符)，
//							NGX_HASH_READONLY_KEY(不可以通过全小写关键字来获取散列码)，
//							其他值表示既不处理关键字，又允许通过把关键字全小写来获取散列码
//	@return -- NGX_OK,表示成功；NGX_ERROR,表示失败
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
