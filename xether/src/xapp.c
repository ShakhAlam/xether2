#include "../include/xapp.h"


struct layer*
allocapplayer(int s)
{
	struct layer *m;
	if(s<=0)
		return NULL;
	if( ( m = calloc(1,sizeof(struct layer)) ) == NULL)
		return NULL;
	if( ( m->proto = malloc( s ) ) == NULL){
		free(m);
		return NULL;
	}
	m->pkthdr = NULL;
	m->size = s;
	m->type = LT_APP;
	m->print = appprint;
	m->sprint = appsprint;
	m->next = NULL;
	return m;
}

struct layer *
app_decode(const char *buf,int len){
	struct layer *m;



	if( len <= 0 )
		return NULL;

	m = allocapplayer(len);

	if(m == NULL )
		return NULL;
	memcpy(m->proto,buf,len);
			
	return m;
}

struct layer *
alloc_app(struct layer *m,int len)
{
	if(m == NULL)
		return NULL;
	
	

	if( ( m->proto = calloc(1,len) ) == NULL){
				free(m);
				return NULL;
	}
	m->size = len;
	m->type = LT_APP;
	m->print = appprint;
	m->sprint = appsprint;

	return m;
}


void
appprint(struct layer *m)
{
	printf("DATA: %d bytes\n",m->size);
	ascii_print(m->proto,m->size);
	puts("");
}

char *
appsprint(char *data,size_t n, struct layer *m)
{
	if(n <= APP_PRINT_BUF)
		return NULL;
	if(ascii_sprint(data,n,m->proto,m->size)==-1)
		return NULL;
	return data;
}
