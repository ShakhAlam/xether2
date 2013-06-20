#ifndef XLAYER_XAPP_HINCLUDED
#define XLAYER_XAPP_HINCLUDED
#include "xlayer.h"

#define APP_PRINT_BUF 8192

struct layer *allocapplayer(int s);
struct layer *app_decode(const char *buf,int len);
struct layer *alloc_app(struct layer *m,int len);
void	appprint(struct layer *m);
char *appsprint(char *data,size_t n, struct layer *m);

#endif
