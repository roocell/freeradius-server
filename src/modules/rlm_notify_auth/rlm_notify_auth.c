#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include "rlm_notify_auth.h"
#include <ctype.h>
#include <curl/curl.h>

#define UNUSED_(x) (void)(x)

typedef struct rlm_notify_auth {
    fr_ipaddr_t fr_ipaddr;
    uint32_t ipaddr;
    uint32_t port;
} rlm_notify_auth_t;


static const CONF_PARSER module_config[] = {
	{ "dest_ip",   FR_CONF_OFFSET(PW_TYPE_IPV4_ADDR, rlm_notify_auth_t, fr_ipaddr), "0" },
	{ "dest_port", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_notify_auth_t, port), "80" },
	CONF_PARSER_TERMINATOR
};


// some curl write function (to get HTTP response)
struct http_data {
  char *ptr;
  size_t len;
};

static void init_string(struct http_data *s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

static size_t writefunc(void *ptr, size_t size, size_t nmemb, void* data)
{
  struct http_data* s=(struct http_data*)data;
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
  rlm_notify_auth_t       *inst = instance;
  //unsigned char replyStr[32];
  WARN("%s:%d", __FILE__, __LINE__);
	UNUSED_(instance);
	UNUSED_(request);

  WARN("%s:%d u:%s p:%s %d", __FILE__, __LINE__,
         (request->username)?request->username->vp_strvalue:"(null)",
         (request->password)?request->password->vp_strvalue:"(null)",
         request->reply->code
       );


  if (request->reply->code == PW_CODE_ACCESS_ACCEPT)
  {
    // send a msg to the APNS server

  } else if (request->reply->code == PW_CODE_ACCESS_REJECT) {
      CURL *curl;
      CURLcode res;
      struct http_data s;
      init_string(&s);

      char url[100];
      char post[100];
      char ipstr[INET_ADDRSTRLEN];

      char srcipstr[INET_ADDRSTRLEN];

      if (request->packet)
      {
        inet_ntop(AF_INET, &(request->packet->src_ipaddr.ipaddr.ip4addr), srcipstr, INET_ADDRSTRLEN);
      } else {
        sprintf(srcipstr, "none");
      }

      inet_ntop(AF_INET, &(inst->ipaddr), ipstr, INET_ADDRSTRLEN);
      sprintf(url, "http://%s:%d/simplepush.php", ipstr, inst->port);
      sprintf(post, "username=%s&apip=%s",
        (request->username)?request->username->vp_strvalue:"unknown",
        srcipstr
        );

      WARN("%s:%d %s?%s", __FILE__, __LINE__, url, post);

      /* get a curl handle */
      curl = curl_easy_init();
      if(curl) {
        /* First set the URL that is about to receive our POST. This URL can
           just as well be a https:// URL if that is what should receive the
           data. */
        curl_easy_setopt(curl, CURLOPT_URL, url);
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);

        // setup where we want to store the reponse
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);


        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);

        /* Check for errors */
        if(res != CURLE_OK) {
          WARN("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        WARN("%s:%d %s", __FILE__, __LINE__, s.ptr);
        free(s.ptr);

        /* always cleanup */
        curl_easy_cleanup(curl);
      }
      // by returning handled here, the reject will not be sent.
      return RLM_MODULE_HANDLED;
  }
  return RLM_MODULE_OK;
}


/*
 * delete all the allocated space by module
 */
static int mod_detach(void *instance)
{
	//rlm_notify_auth_t *inst;
  WARN("notify_auth: %s:%d", __func__, __LINE__);

	//inst = (rlm_notify_auth_t *)instance;
  UNUSED_(instance);

 curl_global_cleanup();

	return 0;
}


static int mod_instantiate(CONF_SECTION *cs, void *instance)
{
	rlm_notify_auth_t	*inst = instance;
char str[INET_ADDRSTRLEN];


	UNUSED_(cs);

inst->ipaddr = *((uint32_t *)(&(inst->fr_ipaddr.ipaddr.ip4addr)));
inet_ntop(AF_INET, &(inst->ipaddr), str, INET_ADDRSTRLEN);
 WARN("notify_auth: %s:%d ipaddr 0x%X[%s]  port %d", __func__, __LINE__, inst->ipaddr, str, inst->port);

curl_global_init(CURL_GLOBAL_ALL);

	return 0;

}


static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
  WARN("notify_auth: %s:%d", __func__, __LINE__);
	UNUSED_(instance);
	UNUSED_(request);

  return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
   WARN("notify_auth: %s:%d", __func__, __LINE__);
	UNUSED_(instance);
	UNUSED_(request);

	return RLM_MODULE_OK;
}


#ifdef WITH_PROXY

static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *instance, REQUEST *request)
{
  WARN("notify_auth: %s:%d", __func__, __LINE__);
	UNUSED_(instance);
	UNUSED_(request);

  return RLM_MODULE_OK;
}
#endif



/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern module_t rlm_notify_auth;
module_t rlm_notify_auth = {
	.magic		= RLM_MODULE_INIT,
	.name		= "notify_auth",
	.inst_size	= sizeof(rlm_notify_auth_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_PROXY
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
