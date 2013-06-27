#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
 DIR *d;
 struct dirent *dirp;
 FILE *fp;
 char *p=0;
 int n;

 if( ( d= opendir(".")) == NULL ){
	perror(*argv);
        exit(1);
 }
 if( ( fp = fopen("makefile","wb") ) == NULL ){
	perror(*argv);
	exit(1);
 }
 fprintf(fp,"%s%s%s",
		"LIBPATH=../lib\n",
		"LIBS=-lxlayer -lpcap\n",
		"INCL=../include\n\n");
 
 while( ( dirp = readdir(d) ) != NULL ){
	n = strlen(dirp->d_name);
	if( n <= 2 )
		continue;
	p = &(dirp->d_name[strlen(dirp->d_name)-1]);
	if( *p == 'c' &&  *(p-1) == '.'){

		*(p-1)= 0;
		p=dirp->d_name;
		fprintf(fp,"%s: %s.o\n\tgcc -o %s %s.o -L$(LIBPATH) $(LIBS)\n",
				p,p,p,p);
		fprintf(fp,"%s.o: %s.c\n\tgcc -c %s.c -I$(INCL)\n",p,p,p);
	}

  }
  closedir(d);
  fclose(fp);
  return 0; 
}
