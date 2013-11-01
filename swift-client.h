#ifndef SWIFT_CLIENT_H_
#define SWIFT_CLIENT_H_

#define _GNU_SOURCE
#include <stdio.h>
#include <malloc.h>
#include <wchar.h>
#include <curl/curl.h>

/**
 * High-level types of errors which can occur while attempting to use Swift.
 * More detail is available from lower-level libraries (such as curl)
 * using error callbacks specific to those libraries.
 */
enum swift_error {
	SCERR_SUCCESS      = 0, /* Success */
	SCERR_INIT_FAILED  = 1, /* Initialisation of this library failed */
	SCERR_INVARG       = 2, /* An invalid argument was supplied */
	SCERR_ALLOC_FAILED = 3, /* memory allocation failed */
	SCERR_URL_FAILED   = 4  /* network operation on a URL failed */
};

/* The subset of HTTP methods used by Swift */
enum http_method {
	GET,
	PUT,
	POST
};

/* A function which allocates memory */
typedef void *(*swift_allocator_func_t)(size_t size);

/* A function which re-allocates memory */
typedef void *(*swift_reallocator_func_t)(void *ptr, size_t newsize);

/* A function which de-allocates memory */
typedef void (*swift_deallocator_func_t)(void *ptr);

/* A function which receives curl errors */
typedef void (*curl_error_callback_t)(const char *curl_funcname, CURLcode res);

/* A function which receives libiconv errors */
typedef void (*iconv_error_callback_t)(const char *iconv_funcname, int iconv_errno);

/* A function which supplies data from somewhere of its choice into memory upon demand */
typedef size_t (*supply_data_func_t)(void *ptr, size_t size, size_t nmemb, void *stream);

/* A function which receives data into somewhere of its choice from memory upon demand */
typedef size_t (*receive_data_func_t)(char *ptr, size_t size, size_t nmemb, void *userdata);

/* swift client library's per-thread private context */
struct swift_context_private {
	CURL *curl;       /* Handle to curl library's easy interface */
	iconv_t iconv;    /* iconv library's conversion descriptor */
	unsigned int ssl; /* True if SSL in use, false otherwise */
	unsigned int verify_cert_trusted;  /* True if the peer's certificate must chain to a trusted CA, false otherwise */
	unsigned int verify_cert_hostname; /* True if the peer's certificate's hostname must be correct, false otherwise */
	char *hostname;   /* hostname or dotted-decimal IP of Swift server */
	unsigned int api_ver; /* Swift API version */
	char *account;    /* Name of current account */
	char *container;  /* Name of current container */
	char *object;     /* Name of current object */
	char *auth_token; /* Authentication token previously obtained from separate authentication service */
	char *url;        /* The URL currently being used */
};

typedef struct swift_context_private swift_context_private_t;

/**
 * All use of this library is performed within a 'context'.
 * Contexts cannot be shared among threads; each thread must have its own context.
 * Your program is responsible for allocating and freeing context structures.
 * Contexts should be zeroed out prior to use.
 */
struct swift_context {

	/* These members are 'public'; your program can (and should) set them at will */

	/**
	 * Called when a libcurl error occurs.
	 * Your program may set this function pointer in order to perform custom error handling.
	 * If this is NULL at the time swift_start is called, a default handler will be used.
	 */
	curl_error_callback_t curl_error;
	/**
	 * Called when a libiconv error occurs.
	 * Your program may set this function in order to perform custom error handling.
	 * If this is NULL at the time swift_start is called, a default handler will be used.
	 */
	iconv_error_callback_t iconv_error;
	/**
	 * Called when this library needs to allocate memory of the given size in bytes.
	 * If this is NULL at the time swift_start is called, a default allocator will be used.
	 */
	swift_allocator_func_t allocator;
	/**
	 * Called when this library needs to re-allocate memory at the given pointer to be the given size.
	 * If this is NULL at the time swift_start is called, a default re-allocator will be used.
	 */
	swift_reallocator_func_t reallocator;
	/**
	 * Called when this library needs to de-allocate memory at the given pointer.
	 * If this is NULL at the time swift_start is called, a default de-allocator will be used.
	 */
	swift_deallocator_func_t deallocator;

	/* This member (and its members, recursively) are 'private'. */
	/* They should not be modified by your program unless you *really* know what you're doing. */
	swift_context_private_t pvt;
};

typedef struct swift_context swift_context_t;

/**
 * Begin using this library.
 * The context passed must be zeroed out, except for the public part,
 * in which you may want to over-ride the function pointers.
 * Function pointers left NULL will be given meaningful defaults.
 * This must be called early in the execution of your program,
 * before additional threads (if any) are created.
 * This must be called before any other use of this library by your program.
 * These restrictions are imposed by libcurl, and the libcurl restrictions are in turn
 * imposed by the libraries that libcurl uses.
 * If your program is a library, it will need to expose a similar API to,
 * and expose similar restrictions on, its users.
 */
enum swift_error swift_global_init(void);

/**
 * Cease using this library.
 * This must be called late in the execution of your program,
 * after all secondary threads (if any) have exited,
 * so that there is precisely one thread in your program at the time of the call.
 * This library must not be used by your program after this function is called.
 * This function must be called exactly once for each successful prior call to swift_init
 * by your program.
 * These restrictions are imposed by libcurl, and the libcurl restrictions are in turn
 * imposed by the libraries that libcurl uses.
 * If your program is a library, it will need to expose a similar API to,
 * and expose similar restrictions on, its users.
 */
void swift_global_cleanup(void);

/**
 * Begin using this library for a single thread of your program.
 * This must be called by each thread of your program in order to use this library.
 */
enum swift_error swift_start(swift_context_t *context);

/**
 * Cease using this library for a single thread.
 * This must be called by each thread of your program after it is finished using this library.
 * Each thread in your program must call this function precisely once for each successful prior call
 * to swift_start by that thread.
 * After this call, the context is invalid.
 */
void swift_end(swift_context_t **context);

/**
 * Set the current Swift server hostname.
 */
enum swift_error swift_set_hostname(swift_context_t *context, const char *hostname);

/**
 * Set the current Swift API version to be spoken with the server.
 */
enum swift_error swift_set_api_version(swift_context_t *context, unsigned int api_version);

/**
 * Control whether the Swift server should be accessed via HTTPS, or just HTTP.
 */
enum swift_error swift_set_ssl(swift_context_t *context, unsigned int use_ssl);

/**
 * Control whether an HTTPS server's certificate is required to chain to a trusted CA cert.
 */
enum swift_error swift_verify_cert_trusted(swift_context_t *context, unsigned int require_trusted_cert);

/**
 * Control whether an HTTPS server's hostname is required to match its certificate's hostname.
 */
enum swift_error swift_verify_cert_hostname(swift_context_t *context, unsigned int require_matching_hostname);

/**
 * Set the name of the current Swift account.
 */
enum swift_error swift_set_account(swift_context_t *context, wchar_t *account_name);

/**
 * Set the value of the authentication token to be supplied with requests.
 * This should have have been obtained previously from a separate authentication service.
 */
enum swift_error swift_set_auth_token(swift_context_t *context, char *auth_token);

/**
 * Set the name of the current Swift container.
 */
enum swift_error swift_set_container(swift_context_t *context, wchar_t *container_name);

/**
 * Set the name of the current Swift object.
 */
enum swift_error swift_set_object(swift_context_t *context, wchar_t *object_name);

/**
 * Retrieve an object from Swift and pass its data to the given callback function.
 */
enum swift_error swift_get(swift_context_t *context, receive_data_func_t receive_data_callback);

/**
 * Insert or update an object in Swift using the data supplied by the given callback function.
 * Optionally, also attach a set of metadata {name, value} tuples to the object.
 * metadata_count specifies the number of {name, value} tuples to be set. This may be zero.
 * If metadata_count is non-zero, metadata_names and metadata_values must be arrays, each of length metadata_count, specifying the {name, value} tuples.
 */
enum swift_error swift_put(swift_context_t *context, supply_data_func_t supply_data_callback, size_t metadata_count, const wchar_t **metadata_names, const wchar_t **metadata_values);

/**
 * Insert or update metadata for the current object.
 * metadata_count specifies the number of {name, value} tuples to be set.
 * metadata_names and metadata_values must be arrays, each of length metadata_count, specifying the {name, value} tuples.
 */
enum swift_error swift_set_metadata(swift_context_t *context, size_t metadata_count, const wchar_t **metadata_names, const wchar_t **metadata_values);

#endif /* SWIFT_CLIENT_H_ */
