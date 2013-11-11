#include <assert.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include "swift-client.h"

/**
 * The maximum length in bytes of a multi-byte UTF-8 sequence.
 *
 */
#define UTF8_SEQUENCE_MAXLEN 6

/* Name of Keystone header containing authentication username */
#define KEYSTONE_AUTH_HEADER_USERNAME "X-Auth-User"
/* Name of Keystone header containing authentication password */
#define KEYSTONE_AUTH_HEADER_PASSWORD "X-Auth-Key"
/* Name in Keystone's service catalog of Swift service */
#define KEYSTONE_SERVICE_TYPE_SWIFT "object-store"

/* Prefix to be prepended to Swift metadata key names in order to generate HTTP headers */
#define SWIFT_METADATA_PREFIX "X-Object-Meta-"
/* Name of HTTP header used to pass authentication token to Swift server */
#define SWIFT_AUTH_HEADER_NAME "X-Auth-Token"
/* Version of Swift API to be used by default */
#define DEFAULT_SWIFT_API_VER 1

/* The portion of a JSON-encoded Keystone credentials POST body preceding the username */
#define KEYSTONE_AUTH_PAYLOAD_BEFORE_USERNAME "\
{\n\
	\"auth\":{\n\
		\"passwordCredentials\":{\n\
			\"username\":\""
/* The portion of a JSON-encoded Keystone credentials POST body succeeding the username and preceding the password */
#define KEYSTONE_AUTH_PAYLOAD_BEFORE_PASSWORD "\",\n\
			\"password\":\""
/* The portion of a JSON-encoded Keystone credentials POST body succeeding the password and preceding the tenant name */
#define KEYSTONE_AUTH_PAYLOAD_BEFORE_TENANT "\"\n\
		},\n\
		\"tenantName\":\""
/* The portion of a JSON-encoded Keystone credentials POST body succeeding the tenant name */
#define KEYSTONE_AUTH_PAYLOAD_END "\"\n\
	}\n\
}"

#ifdef min
#undef min
#endif
#define min(a, b) (((a) < (b)) ? (a) : (b))

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
 * Default handler for libjson errors.
 */
static void
default_json_error_callback(const char *json_funcname, enum json_tokener_error json_err)
{
	assert(json_funcname != NULL);
	assert(json_err != json_tokener_success);
	assert(json_err != json_tokener_continue);
	fprintf(stderr, "%s failed: libjson error %ld: %s\n", json_funcname, (long) json_err, json_tokener_error_desc(json_err));
}

/**
 * Default handler for Keystone errors.
 */
void default_keystone_error_callback(const char *keystone_operation, enum keystone_error keystone_err)
{
	assert(keystone_operation != NULL);
	assert(keystone_err != KSERR_SUCCESS);
	fprintf(stderr, "Keystone: %s: error %ld\n", keystone_operation, (long) keystone_err);
}

/**
 * Default memory [re-/de-]allocator.
 */
static void *
default_allocator(void *ptr, size_t size)
{
	if (0 == size) {
		if (ptr != NULL) {
			free(ptr);
		}
		return NULL;
	}
	if (NULL == ptr) {
		return malloc(size);
	}
	return realloc(ptr, size);
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
	if (!context->json_error) {
		context->json_error = default_json_error_callback;
	}
	if (!context->keystone_error) {
		context->keystone_error = default_keystone_error_callback;
	}
	if (!context->allocator) {
		context->allocator = default_allocator;
	}
	if (!context->pvt.api_ver) {
		context->pvt.api_ver = DEFAULT_SWIFT_API_VER;
	}
	context->pvt.iconv = iconv_open("UTF-8", "WCHAR_T");
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
swift_end(swift_context_t *context)
{
	assert(context != NULL);
	curl_easy_cleanup(context->pvt.curl);
	context->pvt.curl = NULL;
	if (context->pvt.base_url != NULL) {
		context->pvt.base_url = context->allocator(context->pvt.base_url, 0);
	}
	if (context->pvt.container != NULL) {
		context->pvt.container = context->allocator(context->pvt.container, 0);
	}
	if (context->pvt.object != NULL) {
		context->pvt.object = context->allocator(context->pvt.object, 0);
	}
	if (context->pvt.auth_token != NULL) {
		context->pvt.auth_token = context->allocator(context->pvt.auth_token, 0);
	}
	if (context->pvt.auth_payload != NULL) {
		context->pvt.auth_payload = context->allocator(context->pvt.auth_payload, 0);
	}
	if (iconv_close(context->pvt.iconv) < 0) {
		context->iconv_error("iconv_close", errno);
	}
	if (context->pvt.json_tokeniser != NULL) {
		json_tokener_free(context->pvt.json_tokeniser);
		context->pvt.json_tokeniser = NULL;
	}
}

/**
 * Control whether a proxy (eg HTTP or SOCKS) is used to access the Swift server.
 * Argument must be a URL, or NULL if no proxy is to be used.
 */
enum swift_error
swift_set_proxy(swift_context_t *context, const char *proxy_url)
{
	CURLcode curl_err;

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_PROXY, (NULL == proxy_url) ? "" : proxy_url);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_INVARG;
	}

	return SCERR_SUCCESS;
}

/**
 * Control verbose logging to stderr of the actions of this library and the libraries it uses.
 * Currently this enables logging to standard error of libcurl's actions.
 */
enum swift_error
swift_set_debug(swift_context_t *context, unsigned int enable_debugging)
{
	CURLcode curl_err;

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_VERBOSE, enable_debugging ? 1 : 0);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_INVARG;
	}

	return SCERR_SUCCESS;
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
	*out = context->allocator(*out, utf8_in_len);
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
	*out = context->allocator(*out, strlen(url_encoded) + 1 /* '\0' */);
	if (NULL == *out) {
		return SCERR_ALLOC_FAILED;
	}
	strcpy(*out, url_encoded);
	/* Free the URL-encoded copy created by libcurl */
	curl_free(url_encoded);

	return SCERR_SUCCESS;
}

/**
 * Set the current Swift server URL. This must not contain any path information.
 */
enum swift_error
swift_set_url(swift_context_t *context, const char *url)
{
	context->pvt.base_url = context->allocator(context->pvt.base_url, strlen(url) + 1 /* '\0' */);
	if (NULL == context->pvt.base_url) {
		return SCERR_ALLOC_FAILED;
	}
	strcpy(context->pvt.base_url, url);

	return SCERR_SUCCESS;
}

/**
 * Set the current Swift API version to be spoken with the server.
 */
enum swift_error
swift_set_api_version(swift_context_t *context, unsigned int api_version)
{
	context->pvt.api_ver = api_version;

	return SCERR_SUCCESS;
}

/**
 * Control whether an HTTPS server's certificate is required to chain to a trusted CA cert.
 */
enum swift_error
swift_verify_cert_trusted(swift_context_t *context, unsigned int require_trusted_cert)
{
	CURLcode curl_err;

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_SSL_VERIFYPEER, (long) require_trusted_cert);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	return SCERR_SUCCESS;
}

/**
 * Control whether an HTTPS server's hostname is required to match its certificate's hostname.
 */
enum swift_error
swift_verify_cert_hostname(swift_context_t *context, unsigned int require_matching_hostname)
{
	CURLcode curl_err;

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_SSL_VERIFYHOST, (long) require_matching_hostname);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	return SCERR_SUCCESS;
}

/**
 * Set the value of the authentication token to be supplied with requests.
 * This should have been obtained previously from a separate authentication service.
 */
enum swift_error
swift_set_auth_token(swift_context_t *context, char *auth_token)
{
	context->pvt.auth_token = context->allocator(context->pvt.auth_token, strlen(auth_token) + 1 /* '\0' */);
	if (NULL == context->pvt.auth_token) {
		return SCERR_ALLOC_FAILED;
	}
	strcpy(context->pvt.auth_token, auth_token);

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
 * Generate a Swift URL from the current base URL, account, container and object.
 */
static enum swift_error
make_url(swift_context_t *context, enum swift_operation operation)
{
	size_t url_len = context->pvt.base_url_len;

	assert(context != NULL);
	assert(context->pvt.api_ver != 0);
	assert(context->pvt.container != NULL);
	assert(context->pvt.base_url);
	assert(context->pvt.base_url_len);

	switch (operation) {
	case PUT_OBJECT:
	case GET_OBJECT:
	case SET_OBJECT_METADATA:
	case DELETE_OBJECT:
		assert(context->pvt.object != NULL);
		url_len +=
			1 /* '/' */
			+ strlen(context->pvt.object)
		;
		/* no break: fall thru */
	case CREATE_CONTAINER:
	case LIST_CONTAINER:
	case SET_CONTAINER_METADATA:
	case DELETE_CONTAINER:
		url_len +=
			1 /* '/' */
			+ strlen(context->pvt.container)
		;
		break;
	default:
		assert(0);
		return SCERR_INVARG;
	}
	url_len++; /* '\0' */

	context->pvt.base_url = context->allocator(context->pvt.base_url, url_len);
	if (NULL == context->pvt.base_url) {
		return SCERR_ALLOC_FAILED;
	}

	switch (operation) {
	case CREATE_CONTAINER:
	case LIST_CONTAINER:
	case SET_CONTAINER_METADATA:
	case DELETE_CONTAINER:
		sprintf(
			context->pvt.base_url + context->pvt.base_url_len,
			"/%s",
			context->pvt.container
		);
		break;
	case PUT_OBJECT:
	case GET_OBJECT:
	case SET_OBJECT_METADATA:
	case DELETE_OBJECT:
		sprintf(
			context->pvt.base_url + context->pvt.base_url_len,
			"/%s/%s",
			context->pvt.container,
			context->pvt.object
		);
		break;
	default:
		assert(0);
		return SCERR_INVARG;
	}

	return SCERR_SUCCESS;
}

static enum keystone_error
find_keystone_endpoint(swift_context_t *context, struct json_object *endpoints, unsigned int api_version)
{
	int endpoint_count;

	assert(context != NULL);

	if (!json_object_is_type(endpoints, json_type_array)) {
		context->keystone_error("response.access.serviceCatalog[n].endpoints is not an array", KSERR_PARSE);
		return KSERR_PARSE; /* Not the expected JSON array */
	}
	endpoint_count = json_object_array_length(endpoints);
	if (endpoint_count < 0) {
		context->keystone_error("response.access.serviceCatalog[n].endpoints is a negative-length array", KSERR_PARSE);
		return KSERR_PARSE; /* libjson reports a negative-size array?! */
	}
	while (endpoint_count--) {
		struct json_object *endpoint = json_object_array_get_idx(endpoints, endpoint_count), *endpoint_public_url;
		if (NULL == endpoint) {
			context->keystone_error("failed to index into response.access.serviceCatalog[n].endpoints array", KSERR_PARSE);
			return KSERR_PARSE; /* Failed to retrieve endpoint array entry */
		}
		if (!json_object_is_type(endpoint, json_type_object)) {
			context->keystone_error("response.access.serviceCatalog[n].endpoints[n] is not an array", KSERR_PARSE);
			return KSERR_PARSE; /* Not the expected JSON object */
		}
		if (context->pvt.api_ver != 0) {
			/* Looking for a certain version of the Swift RESTful API */
			struct json_object *endpoint_api_version;
			if (json_object_object_get_ex(endpoint, "versionId", &endpoint_api_version)) {
				/* Keystone documentation includes a versionID key, but it is not present in the responses I've seen */
				if (!json_object_is_type(endpoint_api_version, json_type_string)) {
					context->keystone_error("response.access.serviceCatalog[n].endpoints[n].versionId is not a string", KSERR_PARSE);
					return KSERR_PARSE; /* Not the expected JSON string */
				}
				if (json_object_get_double(endpoint_api_version) != api_version) {
					continue; /* Not the API version we're after */
				}
				/* Found the API version we're after */
			} else {
				/* No versionID on service endpoint. Use it anyway */
			}
		} else {
			/* No desired API version currently set, so use the first endpoint found */
		}
		if (!json_object_object_get_ex(endpoint, "publicURL", &endpoint_public_url)) {
			context->keystone_error("response.access.serviceCatalog[n].endpoints[n] lacks a 'publicURL' key", KSERR_PARSE);
			return KSERR_PARSE; /* Lacking the expected key */
		}
		if (!json_object_is_type(endpoint_public_url, json_type_string)) {
			context->keystone_error("response.access.serviceCatalog[n].endpoints[n].publicURL is not a string", KSERR_PARSE);
			return KSERR_PARSE; /* Not the expected JSON string */
		}
		context->pvt.base_url_len = json_object_get_string_len(endpoint_public_url);
		context->pvt.base_url = context->allocator(
			context->pvt.base_url,
			context->pvt.base_url_len
			+ 1 /* '\0' */
		);
		if (NULL == context->pvt.base_url) {
			return KSERR_PARSE; /* Allocation failed */
		}
		strcpy(context->pvt.base_url, json_object_get_string(endpoint_public_url));
		return KSERR_SUCCESS;
	}

	return KSERR_NOTFOUND;
}

/**
 * Retrieve the authentication token and Swift URL from a now-complete JSON response.
 */
static enum keystone_error
process_keystone_json(swift_context_t *context, struct json_object *jobj)
{
	struct json_object *subobj;

	int service_count;
	/* json_object_to_file_ext("/dev/stderr", jobj, JSON_C_TO_STRING_PRETTY); */
	if (!json_object_is_type(jobj, json_type_object)) {
		context->keystone_error("response not a JSON object", KSERR_PARSE);
		return KSERR_PARSE; /* Not the expected JSON object */
	}
	/* Authentication token */
	if (!json_object_object_get_ex(jobj, "access", &subobj)) {
		context->keystone_error("response lacks 'access' key", KSERR_PARSE);
		return KSERR_PARSE; /* Lacking the expected key */
	}
	if (!json_object_is_type(subobj, json_type_object)) {
		context->keystone_error("response.access not an object", KSERR_PARSE);
		return KSERR_PARSE; /* Not the expected JSON object */
	}
	if (!json_object_object_get_ex(subobj, "token", &subobj)) {
		context->keystone_error("reponse.access lacks 'token' key", KSERR_PARSE);
		return KSERR_PARSE; /* Lacking the expected key */
	}
	if (!json_object_is_type(subobj, json_type_object)) {
		context->keystone_error("response.access.token not an object", KSERR_PARSE);
		return KSERR_PARSE; /* Not the expected JSON object */
	}
	if (!json_object_object_get_ex(subobj, "id", &subobj)) {
		context->keystone_error("response.access.token lacks 'id' key", KSERR_PARSE);
		return KSERR_PARSE; /* Lacking the expected key */
	}
	if (!json_object_is_type(subobj, json_type_string)) {
		context->keystone_error("response.access.token.id not a string", KSERR_PARSE);
		return KSERR_PARSE; /* Not the expected JSON string */
	}
	context->pvt.auth_token = context->allocator(
		context->pvt.auth_token,
		json_object_get_string_len(subobj)
		+ 1 /* '\0' */
	);
	if (NULL == context->pvt.auth_token) {
		return KSERR_PARSE; /* Allocation failed */
	}
	strcpy(context->pvt.auth_token, json_object_get_string(subobj));
	/* Swift URL */
	if (!json_object_object_get_ex(jobj, "access", &subobj)) {
		context->keystone_error("response lacks 'access' key", KSERR_PARSE);
		return KSERR_PARSE; /* Lacking the expected key */
	}
	if (!json_object_is_type(subobj, json_type_object)) {
		context->keystone_error("response.access not an object", KSERR_PARSE);
		return KSERR_PARSE; /* Not the expected JSON object */
	}
	if (!json_object_object_get_ex(subobj, "serviceCatalog", &subobj)) {
		context->keystone_error("response.access lacks 'serviceCatalog' key", KSERR_PARSE);
		return KSERR_PARSE; /* Lacking the expected key */
	}
	if (!json_object_is_type(subobj, json_type_array)) {
		context->keystone_error("response.access.serviceCatalog not an array", KSERR_PARSE);
		return KSERR_PARSE; /* Not the expected JSON array */
	}
	service_count = json_object_array_length(subobj);
	if (service_count < 0) {
		context->keystone_error("response.access.serviceCatalog is a negative-length array", KSERR_PARSE);
		return KSERR_PARSE; /* libjson reports a negative-size array?! */
	}
	while (service_count--) {
		struct json_object *service = json_object_array_get_idx(subobj, service_count), *service_subobj;
		enum keystone_error ks_err;
		if (NULL == service) {
			context->keystone_error("failed to index into response.access.serviceCatalog array", KSERR_PARSE);
			return KSERR_PARSE; /* Failed to retrieve service catalog entry */
		}
		if (!json_object_is_type(service, json_type_object)) {
			context->keystone_error("response.access.serviceCatalog[n] is not an object", KSERR_PARSE);
			return KSERR_PARSE; /* Not the expected JSON object */
		}
		if (!json_object_object_get_ex(service, "type", &service_subobj)) {
			context->keystone_error("response.access.serviceCatalog[n] lacks a 'type' key", KSERR_PARSE);
			return KSERR_PARSE; /* Lacking the expected key */
		}
		if (!json_object_is_type(service_subobj, json_type_string)) {
			context->keystone_error("response.access.serviceCatalog[n].type is not a string", KSERR_PARSE);
			return KSERR_PARSE; /* Not the expected JSON object */
		}
		if (0 != strcmp(json_object_get_string(service_subobj), KEYSTONE_SERVICE_TYPE_SWIFT)) {
			continue; /* Not the service type we're after */
		}
		if (!json_object_object_get_ex(service, "endpoints", &service_subobj)) {
			context->keystone_error("response.access.serviceCatalog[n] lacks an 'endpoints' key", KSERR_PARSE);
			return KSERR_PARSE; /* Lacking the expected key */
		}
		ks_err = find_keystone_endpoint(context, service_subobj, context->pvt.api_ver);
		if (KSERR_SUCCESS == ks_err) {
			break;
		}
		return KSERR_PARSE;
	}

	return KSERR_SUCCESS;
}

/**
 * Process a Keystone authentication response.
 * This parses the response and saves copies of the interesting service endpoint URLs.
 */
static size_t
process_keystone_response(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	swift_context_t *context = (swift_context_t *) userdata;
	const char *body = (const char *) ptr;
	size_t len = size * nmemb;
	struct json_object *jobj;
	enum json_tokener_error json_err;

	jobj = json_tokener_parse_ex(context->pvt.json_tokeniser, body, len);
	json_err = json_tokener_get_error(context->pvt.json_tokeniser);
	if (json_tokener_success == json_err) {
		enum swift_error sc_err = process_keystone_json(context, jobj);
		if (sc_err != SCERR_SUCCESS) {
			return 0; /* Failed to process JSON. Inform libcurl no data 'handled' */
		}
	} else if (json_tokener_continue == json_err) {
		/* Complete JSON response not yet received; continue */
	} else {
		context->json_error("json_tokener_parse_ex", json_err);
		context->keystone_error("failed to parse response", KSERR_PARSE);
		return 0; /* Apparent JSON parsing problem. Inform libcurl no data 'handled' */
	}

	return len; /* Inform libcurl that all data were 'handled' */
}

/**
 * Authenticate against a Keystone authentication server with the given tenant and user names and password.
 * This yields an authorisation token, which is then used to access all Swift services.
 */
enum swift_error
keystone_authenticate(swift_context_t *context, const char *url, const char *tenant_name, const char *username, const char *password)
{
	CURLcode curl_err;
	struct curl_slist *headers = NULL;
	size_t body_len =
		strlen(KEYSTONE_AUTH_PAYLOAD_BEFORE_USERNAME)
		+ strlen(username)
		+ strlen(KEYSTONE_AUTH_PAYLOAD_BEFORE_PASSWORD)
		+ strlen(password)
		+ strlen(KEYSTONE_AUTH_PAYLOAD_BEFORE_TENANT)
		+ strlen(tenant_name)
		+ strlen(KEYSTONE_AUTH_PAYLOAD_END)
	;

	/* Create or reset the JSON tokeniser */
	if (NULL == context->pvt.json_tokeniser) {
		context->pvt.json_tokeniser = json_tokener_new();
		if (NULL == context->pvt.json_tokeniser) {
			context->keystone_error("json_tokener_new failed", KSERR_INIT_FAILED);
			return SCERR_INIT_FAILED;
		}
	} else {
		json_tokener_reset(context->pvt.json_tokeniser);
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_URL, url);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POST, 1L);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	/* Append header specifying body content type (since this differs from libcurl's default) */
	/* Each of XML and JSON is allowed; we use JSON as it's less verbose and simpler to parse */
	headers = curl_slist_append(headers, "Content-Type: application/json");

	/* Append pseudo-header defeating libcurl's default addition of an "Expect: 100-continue" header. */
	headers = curl_slist_append(headers, "Expect:");

	/* Generate POST request body containing the authentication credentials */
	context->pvt.auth_payload = context->allocator(
		context->pvt.auth_payload,
		body_len
		+ 1 /* '\0' */
	);
	if (NULL == context->pvt.auth_payload) {
		curl_slist_free_all(headers);
		return SCERR_ALLOC_FAILED;
	}
	sprintf(context->pvt.auth_payload, "%s%s%s%s%s%s%s",
		KEYSTONE_AUTH_PAYLOAD_BEFORE_USERNAME,
		username,
		KEYSTONE_AUTH_PAYLOAD_BEFORE_PASSWORD,
		password,
		KEYSTONE_AUTH_PAYLOAD_BEFORE_TENANT,
		tenant_name,
		KEYSTONE_AUTH_PAYLOAD_END
	);

	/* Pass the POST request body to libcurl. The data are not copied, so they must persist during the request lifetime. */
	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POSTFIELDS, context->pvt.auth_payload);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return SCERR_URL_FAILED;
	}

#if 0
	/* Add header specifying length of authentication token POST body */
	{
		char content_length_header[16 /* "Content-Length: " */ + 3 /* 999 */ + 1 /* '\0' */];
		sprintf(content_length_header, "Content-Length: %lu", (unsigned long) body_len);
		headers = curl_slist_append(headers, content_length_header);
	}
#else
	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POSTFIELDSIZE, body_len);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return SCERR_URL_FAILED;
	}
#endif

	/* Add header requesting response in JSON */
	headers = curl_slist_append(headers, "Accept: application/json");

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_HTTPHEADER, headers);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_WRITEFUNCTION, process_keystone_response);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_WRITEDATA, context);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_perform(context->pvt.curl);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_perform", curl_err);
		curl_slist_free_all(headers);
		return SCERR_URL_FAILED;
	}

	curl_slist_free_all(headers);

	if (NULL == context->pvt.auth_token) {
		return SCERR_AUTH_FAILED;
	}

	return SCERR_SUCCESS;
}

/**
 * Execute a Swift request using the current protocol, hostname, API version, account, container and object,
 * and using the given HTTP method.
 * This is the portion of the request code that is common to all Swift API operations.
 * This function consumes headers.
 */
static enum swift_error
swift_request(swift_context_t *context, enum swift_operation operation, struct curl_slist *headers, supply_data_func_t produce_request_callback, void *produce_request_callback_arg, receive_data_func_t consume_response_callback, void *consume_response_callback_arg)
{
	CURLcode curl_err;
	enum swift_error sc_err;

	assert(context != NULL);
	sc_err = make_url(context, operation);
	if (sc_err != SCERR_SUCCESS) {
		return sc_err;
	}

	/* FIXME: Failed attempt to prevent libcurl from uselessly using chunked transfer encoding for empty request bodies */
	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POSTFIELDS, NULL);
	if (CURLE_OK != curl_err) {
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POSTFIELDSIZE, 0);
	if (CURLE_OK != curl_err) {
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_READFUNCTION, produce_request_callback);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_READDATA, produce_request_callback_arg);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_WRITEFUNCTION, consume_response_callback);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_WRITEDATA, consume_response_callback_arg);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_URL, context->pvt.base_url);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}
	/* Set HTTP request method */
	{
		CURLoption curl_opt;
		union {
			long longval;
			const char *stringval;
		} curl_param;

		switch (operation) {
		case LIST_CONTAINER:
		case GET_OBJECT:
			/* method GET */
			curl_opt = CURLOPT_HTTPGET;
			curl_param.longval = 1L;
			break;
		case CREATE_CONTAINER:
		case PUT_OBJECT:
			/* method PUT */
			curl_opt = CURLOPT_UPLOAD; /* Causes libcurl to use HTTP PUT method */
			curl_param.longval = 1L;
			break;
		case SET_CONTAINER_METADATA:
		case SET_OBJECT_METADATA:
			/* method POST */
			curl_opt = CURLOPT_POST;
			curl_param.longval = 1L;
			break;
		case DELETE_CONTAINER:
		case DELETE_OBJECT:
			/* method DELETE */
			curl_opt = CURLOPT_CUSTOMREQUEST; /* Causes libcurl to use the given-named HTTP method */
			curl_param.stringval = "DELETE";
			break;
		default:
			/* Unrecognised Swift operation type */
			assert(0);
			return SCERR_INVARG;
		}
		curl_err = curl_easy_setopt(context->pvt.curl, curl_opt, curl_param);
		if (CURLE_OK != curl_err) {
			context->curl_error("curl_easy_setopt", curl_err);
			return SCERR_URL_FAILED;
		}
	}
	/* Append common headers to those requested by caller */
	{
		char *header = NULL;

		header = context->allocator(
			header,
			strlen(SWIFT_AUTH_HEADER_NAME)
			+ 2 /* ": " */
			+ strlen(context->pvt.auth_token)
			+ 1 /* '\0' */
		);
		if (NULL == header) {
			return SCERR_ALLOC_FAILED;
		}
		sprintf(header, SWIFT_AUTH_HEADER_NAME ": %s", context->pvt.auth_token);
		headers = curl_slist_append(headers, header);
		context->allocator(header, 0);
	}

	/* Append pseudo-header defeating libcurl's default addition of an "Expect: 100-continue" header. */
	headers = curl_slist_append(headers, "Expect:");

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_HTTPHEADER, headers);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return SCERR_URL_FAILED;
	}

	curl_err = curl_easy_perform(context->pvt.curl);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_perform", curl_err);
		return SCERR_URL_FAILED;
	}

	curl_slist_free_all(headers);

	return SCERR_SUCCESS;
}

/* Null response consumer. Completely ignores the entire response */
static size_t
ignore_response(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	return size * nmemb;
}

/* Null request producer. Supplies a zero-length body */
static size_t
empty_request(void *ptr, size_t size, size_t nmemb, void *arg)
{
	return 0;
}

/**
 * Retrieve an object from Swift and pass its data to the given callback function.
 */
enum swift_error
swift_get(swift_context_t *context, receive_data_func_t receive_data_callback, void *callback_arg)
{
	assert(context);
	assert(context->pvt.auth_token);

	return swift_request(context, GET_OBJECT, NULL, empty_request, NULL, receive_data_callback, callback_arg);
}

/**
 * Add Swift metadata headers to a request.
 * tuple_count specifies the number of {name, value} tuples to be set.
 * names and values must be arrays, each of length tuple_count, specifying the names and values respectively.
 * */
static enum swift_error
add_metadata_headers(struct swift_context *context, struct curl_slist **headers, size_t tuple_count, const wchar_t **names, const wchar_t **values)
{
	char *header, *iconv_in, *iconv_out;
	size_t iconv_in_len, iconv_out_len;

	header = NULL;
	while (tuple_count--) {
		header = context->allocator(
			header,
			strlen(SWIFT_METADATA_PREFIX)
			+ wcslen(names[tuple_count]) * UTF8_SEQUENCE_MAXLEN /* Assume worst-case expansion */
			+ 2 /* ": " */
			+ wcslen(values[tuple_count]) * UTF8_SEQUENCE_MAXLEN /* Assume worst-case expansion */
			+ 1 /* '\0' */
		);
		if (NULL == header) {
			curl_slist_free_all(*headers);
			context->allocator(header, 0);
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
			curl_slist_free_all(*headers);
			context->allocator(header, 0);
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
			curl_slist_free_all(*headers);
			context->allocator(header, 0);
			return SCERR_INVARG;
		}
		*headers = curl_slist_append(*headers, header);
	}
	context->allocator(header, 0);

	return SCERR_SUCCESS;
}

/**
 * Create a Swift container with the current container name.
 */
enum swift_error
swift_create_container(swift_context_t *context)
{
	assert(context);
	assert(context->pvt.auth_token);

	/* TODO: Optional container metadata */

	return swift_request(context, CREATE_CONTAINER, NULL, empty_request, NULL, ignore_response, NULL);
}

/**
 * Delete the Swift container with the current container name.
 */
enum swift_error
swift_delete_container(swift_context_t *context)
{
	assert(context);
	assert(context->pvt.auth_token);

	return swift_request(context, DELETE_CONTAINER, NULL, empty_request, NULL, ignore_response, NULL);
}

/**
 * Insert or update an object in Swift using the data supplied by the given callback function.
 * Optionally, also attach a set of metadata {name, value} tuples to the object.
 * metadata_count specifies the number of {name, value} tuples to be set. This may be zero.
 * If metadata_count is non-zero, metadata_names and metadata_values must be arrays, each of length metadata_count, specifying the {name, value} tuples.
 */
enum swift_error
swift_put(swift_context_t *context, supply_data_func_t supply_data_callback, void *callback_arg, size_t metadata_count, const wchar_t **metadata_names, const wchar_t **metadata_values)
{
	enum swift_error sc_err;
	struct curl_slist *headers = NULL;

	assert(context);
	assert(context->pvt.auth_token);

	sc_err = add_metadata_headers(context, &headers, metadata_count, metadata_names, metadata_values);
	if (SCERR_SUCCESS != sc_err) {
		return sc_err;
	}

	return swift_request(context, PUT_OBJECT, headers, supply_data_callback, callback_arg, ignore_response, NULL);
}

static size_t
supply_data_from_file(void *ptr, size_t size, size_t nmemb, void *stream)
{
	return fread(ptr, size, nmemb, (FILE *) stream);
}

/**
 * Insert or update an object in Swift using the data in the given-names file.
 * Optionally, also attach a set of metadata {name, value} tuples to the object.
 * metadata_count specifies the number of {name, value} tuples to be set. This may be zero.
 * If metadata_count is non-zero, metadata_names and metadata_values must be arrays, each of length metadata_count, specifying the {name, value} tuples.
 */
enum swift_error
swift_put_file(swift_context_t *context, const char *filename, size_t metadata_count, const wchar_t **metadata_names, const wchar_t **metadata_values)
{
	FILE *stream;
	enum swift_error swift_err;

	stream = fopen(filename, "rb");
	if (NULL == stream) {
		perror("fopen");
		return SCERR_FILEIO_FAILED;
	}

	swift_err = swift_put(context, supply_data_from_file, stream, metadata_count, metadata_names, metadata_values);

	if (fclose(stream) != 0) {
		swift_err = SCERR_FILEIO_FAILED;
	}

	return swift_err;
}

struct data_from_mem_args {
	const unsigned char *ptr;
	size_t nleft;
};

static size_t
supply_data_from_memory(void *ptr, size_t size, size_t nmemb, void *cookie)
{
	struct data_from_mem_args *args = (struct data_from_mem_args *) cookie;
	size_t len = min(size * nmemb, args->nleft);

	memcpy(ptr, args->ptr, len);
	args->ptr += len;
	args->nleft -= len;

	return len;
}

/**
 * Insert or update an object in Swift using the size bytes of data located in memory at ptr.
 * Optionally, also attach a set of metadata {name, value} tuples to the object.
 * metadata_count specifies the number of {name, value} tuples to be set. This may be zero.
 * If metadata_count is non-zero, metadata_names and metadata_values must be arrays, each of length metadata_count, specifying the {name, value} tuples.
 */
enum swift_error
swift_put_data_memory(swift_context_t *context, const unsigned char *ptr, size_t size, size_t metadata_count, const wchar_t **metadata_names, const wchar_t **metadata_values)
{
	struct data_from_mem_args args;

	args.ptr = ptr;
	args.nleft = size;

	return swift_put(context, supply_data_from_memory, &args, metadata_count, metadata_names, metadata_values);
}

/**
 * Insert or update metadata for the current object.
 * metadata_count specifies the number of {name, value} tuples to be set.
 * metadata_names and metadata_values must be arrays, each of length metadata_count, specifying the {name, value} tuples.
 */
enum swift_error
swift_set_metadata(swift_context_t *context, size_t metadata_count, const wchar_t **metadata_names, const wchar_t **metadata_values)
{
	enum swift_error sc_err;
	struct curl_slist *headers = NULL;

	assert(context != NULL);
	assert(metadata_names != NULL);
	assert(metadata_values != NULL);

	if (0 == metadata_count) {
		return SCERR_SUCCESS; /* Nothing to do */
	}

	sc_err = add_metadata_headers(context, &headers, metadata_count, metadata_names, metadata_values);
	if (SCERR_SUCCESS != sc_err) {
		return sc_err;
	}

	return swift_request(context, SET_OBJECT_METADATA, headers, empty_request, NULL, ignore_response, NULL);
}

/**
 * Delete the Swift object with the current container and object names.
 */
enum swift_error
swift_delete_object(swift_context_t *context)
{
	assert(context);
	assert(context->pvt.auth_token);

	return swift_request(context, DELETE_OBJECT, NULL, empty_request, NULL, ignore_response, NULL);
}
