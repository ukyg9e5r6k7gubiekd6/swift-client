#include <assert.h>
#include <string.h>
#include <iconv.h>
#include <errno.h>

#include "swift-client.h"

/**
 * The maximum length in bytes of a multi-byte UTF-8 sequence.
 *
 */
#define UTF8_SEQUENCE_MAXLEN 6

/* Prefix to be prepended to Swift metadata key names in order to generate HTTP headers */
#define SWIFT_METADATA_PREFIX "X-Object-Meta-"

/**
 * Default handler for libcurl errors.
 */
static void
default_curl_error_callback(const char *curl_funcname, CURLcode curl_err)
{
	assert(curl_funcname != NULL);
	fprintf(stderr, "%s failed: libcurl error code %ld: %s\n", curl_funcname, (long) curl_err, curl_easy_strerror(curl_err));
}

/**
 * Default handler for libiconv errors.
 */
static void
default_iconv_error_callback(const char *iconv_funcname, int iconv_errno)
{
	assert(iconv_funcname != NULL);
	errno = iconv_errno;
	perror(iconv_funcname);
}

/**
 * Default memory allocator.
 */
static void *
default_allocator(size_t size)
{
	return malloc(size);
}

/**
 * Default memory re-allocator.
 */
static void *
default_reallocator(void *ptr, size_t newsize)
{
	return realloc(ptr, newsize);
}

/**
 * Default memory de-allocator.
 */
static void
default_deallocator(void *ptr)
{
	free(ptr);
}

/**
 * To be called at start of user program, while still single-threaded.
 * Non-thread-safe and non-re-entrant.
 */
enum swift_error
swift_global_init(void)
{
	CURLcode curl_err;

	curl_err = curl_global_init(CURL_GLOBAL_ALL);
	if (curl_err != 0) {
		/* TODO: Output error indications about detected error in 'res' */
		return SCERR_INIT_FAILED;
	}

	return SCERR_SUCCESS;
}

/**
 * To be called at end of user program, while again single-threaded.
 * Non-thread-safe and non-re-entrant.
 */
void
swift_global_cleanup(void)
{
	curl_global_cleanup();
}

/**
 * To be called by each thread of user program that will use this library,
 * before first other use of this library.
 * Thread-safe and re-entrant.
 */
enum swift_error
swift_start(swift_context_t *context)
{
	assert(context != NULL);
	if (!context->curl_error) {
		context->curl_error = default_curl_error_callback;
	}
	if (!context->iconv_error) {
		context->iconv_error = default_iconv_error_callback;
	}
	if (!context->allocator) {
		context->allocator = default_allocator;
	}
	if (!context->reallocator) {
		context->reallocator = default_reallocator;
	}
	if (!context->deallocator) {
		context->deallocator = default_deallocator;
	}
	context->pvt.iconv = iconv_open("WCHAR_T", "UTF-8");
	if ((iconv_t) -1 == context->pvt.iconv) {
		context->iconv_error("iconv_open", errno);
		return SCERR_INIT_FAILED;
	}
	context->pvt.curl = curl_easy_init();
	if (NULL == context->pvt.curl) {
		/* NOTE: No error code from libcurl, so we assume/invent CURLE_FAILED_INIT */
		context->curl_error("curl_easy_init", CURLE_FAILED_INIT);
		return SCERR_INIT_FAILED;
	}

	return SCERR_SUCCESS;
}

/**
 * To be called by each thread of user program that will use this library,
 * after last other use of this library.
 * To be called once per successful call to swift_start by that thread.
 * Thread-safe and re-entrant.
 */
void
swift_end(swift_context_t **context)
{
	assert(context != NULL);
	assert(*context != NULL);
	curl_easy_cleanup((*context)->pvt.curl);
	(*context)->pvt.curl = NULL;
	if ((*context)->pvt.url != NULL) {
		(*context)->deallocator((*context)->pvt.url);
		(*context)->pvt.url = NULL;
	}
	if ((*context)->pvt.hostname != NULL) {
		(*context)->deallocator((*context)->pvt.hostname);
		(*context)->pvt.hostname = NULL;
	}
	if ((*context)->pvt.container != NULL) {
		(*context)->deallocator((*context)->pvt.container);
		(*context)->pvt.container = NULL;
	}
	if ((*context)->pvt.object != NULL) {
		(*context)->deallocator((*context)->pvt.object);
		(*context)->pvt.object = NULL;
	}
	if (iconv_close((*context)->pvt.iconv) < 0) {
		(*context)->iconv_error("iconv_close", errno);
	}
	*context = NULL;
}

/**
 * Given a wide string in in, convert it to UTF-8,
 * then URL encode the UTF-8 bytes,
 * then store the result in out.
 */
static enum swift_error
utf8_and_url_encode(swift_context_t *context, const wchar_t *in, char **out)
{
	char *url_encoded, *iconv_in, *iconv_out;
	size_t in_len, utf8_in_len, iconv_in_len, iconv_out_len;

	assert(context != NULL);
	assert(in != NULL);
	assert(out != NULL);
	/* Convert the wchar_t input to UTF-8 and write the result to out */
	in_len = wcslen(in);
	utf8_in_len = in_len * UTF8_SEQUENCE_MAXLEN; /* Assuming worst-case UTF-8 expansion */
	*out = context->reallocator(*out, utf8_in_len);
	if (NULL == *out) {
		return SCERR_ALLOC_FAILED;
	}
	iconv_in_len = in_len * sizeof(wchar_t); /* iconv counts in bytes not chars */
	iconv_out_len = utf8_in_len;
	iconv_in = (char *) in;
	iconv_out = *out;
	if ((size_t) -1 == iconv(context->pvt.iconv, &iconv_in, &iconv_in_len, &iconv_out, &iconv_out_len)) {
		/* This should be impossible, as all wchar_t values should be expressible in UTF-8 */
		context->iconv_error("iconv", errno);
		return SCERR_INVARG;
	}
	/* Create a URL-encoded copy of out in memory newly-allocated by libcurl */
	url_encoded = curl_easy_escape(context->pvt.curl, *out, in_len);
	if (NULL == url_encoded) {
		return SCERR_ALLOC_FAILED;
	}
	/* Copy the URL-encoded value into out, over-writing its previous UTF-8 value */
	*out = context->reallocator(*out, strlen(url_encoded) + 1 /* '\0' */);
	if (NULL == *out) {
		return SCERR_ALLOC_FAILED;
	}
	strcpy(*out, url_encoded);
	/* Free the URL-encoded copy created by libcurl */
	curl_free(url_encoded);

	return SCERR_SUCCESS;
}

/**
 * Set the current Swift server hostname.
 */
enum swift_error
swift_set_hostname(swift_context_t *context, const char *hostname)
{
	context->pvt.hostname = context->reallocator(context->pvt.hostname, strlen(hostname) + 1 /* '\0' */);
	if (NULL == context->pvt.hostname) {
		return SCERR_ALLOC_FAILED;
	}
	strcpy(context->pvt.hostname, hostname);

	return SCERR_SUCCESS;
}

/**
 * Control whether the Swift server should be accessed via HTTPS, or just HTTP.
 */
enum swift_error
swift_set_ssl(swift_context_t *context, unsigned int use_ssl)
{
	context->pvt.ssl = !!use_ssl;

	return SCERR_SUCCESS;
}

/**
 * Control whether an HTTPS server's certificate is required to chain to a trusted CA cert.
 */
enum swift_error
swift_verify_cert_trusted(swift_context_t *context, unsigned int require_trusted_cert)
{
	context->pvt.verify_cert_trusted = !!require_trusted_cert;

	return SCERR_SUCCESS;
}

/**
 * Control whether an HTTPS server's hostname is required to match its certificate's hostname.
 */
enum swift_error
swift_verify_cert_hostname(swift_context_t *context, unsigned int require_matching_hostname)
{
	context->pvt.verify_cert_hostname = !!require_matching_hostname;

	return SCERR_SUCCESS;
}

/**
 * Set the name of the current Swift container.
 */
enum swift_error
swift_set_container(swift_context_t *context, wchar_t *container_name)
{
	return utf8_and_url_encode(context, container_name, &context->pvt.container);
}

/**
 * Set the name of the current Swift object.
 */
enum swift_error
swift_set_object(swift_context_t *context, wchar_t *object_name)
{
	return utf8_and_url_encode(context, object_name, &context->pvt.object);
}

/**
 * Generate a Swift URL from the current protocol, hostname, container and object.
 */
static enum swift_error
make_url(swift_context_t *context)
{
	assert(context != NULL);
	assert(context->pvt.hostname != NULL);
	assert(context->pvt.container != NULL);
	assert(context->pvt.object != NULL);
	context->pvt.url = context->reallocator(
		context->pvt.url,
		4 /* "http" */
		+ (context->pvt.ssl ? 1 : 0) /* 's'? */
		+ 3 /* "://" */
		+ strlen(context->pvt.hostname)
		+ 1 /* '/' */
		+ strlen(context->pvt.container)
		+ 1 /* '/' */
		+ strlen(context->pvt.object)
		+ 1 /* '\0' */
	);
	if (NULL == context->pvt.url) {
		return SCERR_ALLOC_FAILED;
	}
	sprintf(
		context->pvt.url,
		"http%s://%s/%s/%s",
		(context->pvt.ssl ? "s" : ""),
		context->pvt.hostname,
		context->pvt.container,
		context->pvt.object
	);

	return SCERR_SUCCESS;
}

/**
 * Execute a Swift request using the current protocol, hostname, container and object,
 * and using the given HTTP method.
 */
static enum swift_error
swift_request(swift_context_t *context, enum http_method method)
{
	CURLcode curl_err;
	enum swift_error sc_err;

	assert(context != NULL);
	sc_err = make_url(context);
	if (sc_err != SCERR_SUCCESS) {
		return sc_err;
	}
	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_SSL_VERIFYPEER, (long) (context->pvt.ssl && context->pvt.verify_cert_trusted));
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}
	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_SSL_VERIFYHOST, (long) (context->pvt.ssl && context->pvt.verify_cert_hostname));
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}
	curl_easy_setopt(context->pvt.curl, CURLOPT_URL, context->pvt.url);
	switch (method) {
	case GET:
		break; /* this is libcurl's default */
	case PUT:
		curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_PUT, 1L);
		if (CURLE_OK != curl_err) {
			context->curl_error("curl_easy_setopt", curl_err);
			return SCERR_URL_FAILED;
		}
		break;
	case POST:
		curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POST, 1L);
		if (CURLE_OK != curl_err) {
			context->curl_error("curl_easy_setopt", curl_err);
			return SCERR_URL_FAILED;
		}
		break;
	default:
		assert(0);
		break;
	}
	curl_err = curl_easy_perform(context->pvt.curl);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_perform", curl_err);
		return SCERR_URL_FAILED;
	}

	return SCERR_SUCCESS;
}

/**
 * Retrieve an object from Swift and pass its data to the given callback function.
 */
enum swift_error
swift_get(swift_context_t *context, receive_data_func_t receive_data_callback)
{
	CURLcode curl_err;

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_WRITEFUNCTION, receive_data_callback);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	return swift_request(context, GET);
}

/**
 * Insert or update an object in Swift using the data supplied by the given callback function.
 */
enum swift_error
swift_put(swift_context_t *context, supply_data_func_t supply_data_callback)
{
	CURLcode curl_err;

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_READFUNCTION, supply_data_callback);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	return swift_request(context, PUT);
}

/**
 * Insert or update metadata for the current object.
 * tuple_count specifies the number of {name, value} tuples to be set.
 * names and values must be arrays, each of length tuple_count, specifying the names and values respectively.
 */
enum swift_error
swift_set_metadata(swift_context_t *context, size_t tuple_count, wchar_t **names, wchar_t **values)
{
	CURLcode curl_err;
	enum swift_error sc_err;
	struct curl_slist *curl_list = NULL;
	char *header, *iconv_in, *iconv_out;
	size_t iconv_in_len, iconv_out_len;

	assert(context != NULL);
	assert(names != NULL);
	assert(values != NULL);

	if (0 == tuple_count) {
		return SCERR_SUCCESS;
	}
	header = NULL;
	while (tuple_count--) {
		header = context->reallocator(
			header,
			strlen(SWIFT_METADATA_PREFIX)
			+ wcslen(names[tuple_count]) * UTF8_SEQUENCE_MAXLEN /* Assume worst-case expansion */
			+ 2 /* ": " */
			+ wcslen(values[tuple_count]) * UTF8_SEQUENCE_MAXLEN /* Assume worst-case expansion */
			+ 1 /* '\0' */
		);
		if (NULL == header) {
			curl_slist_free_all(curl_list);
			return SCERR_ALLOC_FAILED;
		}
		strcpy(header, SWIFT_METADATA_PREFIX);
		/* NOTE: OpenStack Swift docs don't mention converting name and value to UTF-8, but we do it anyway */
		iconv_in = (char *) names[tuple_count];
		iconv_in_len = (wcslen(names[tuple_count]) + 1) * sizeof(wchar_t); /* iconv counts in bytes not chars */
		iconv_out = &header[strlen(header)];
		iconv_out_len = wcslen(names[tuple_count]) * UTF8_SEQUENCE_MAXLEN + 1 /* '\0' */;
		if ((size_t) -1 == iconv(context->pvt.iconv, &iconv_in, &iconv_in_len, &iconv_out, &iconv_out_len)) {
			/* This should be impossible, as all wchar_t values should be expressible in UTF-8 */
			context->iconv_error("iconv", errno);
			curl_slist_free_all(curl_list);
			context->deallocator(header);
			return SCERR_INVARG;
		}
		strcat(header, ": ");
		iconv_in = (char *) values[tuple_count];
		iconv_in_len = (wcslen(values[tuple_count]) + 1) * sizeof(wchar_t); /* iconv counts in bytes not chars */
		iconv_out = &header[strlen(header)];
		iconv_out_len = wcslen(values[tuple_count]) * UTF8_SEQUENCE_MAXLEN + 1 /* '\0' */;
		if ((size_t) -1 == iconv(context->pvt.iconv, &iconv_in, &iconv_in_len, &iconv_out, &iconv_out_len)) {
			/* This should be impossible, as all wchar_t values should be expressible in UTF-8 */
			context->iconv_error("iconv", errno);
			curl_slist_free_all(curl_list);
			context->deallocator(header);
			return SCERR_INVARG;
		}
		curl_list = curl_slist_append(curl_list, header);
	}
	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_HTTPHEADER, curl_list);
	context->deallocator(header);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}
	sc_err = swift_request(context, POST);
	curl_slist_free_all(curl_list);

	return sc_err;
}
