#define WIN32 1

#include <stdio.h>
#include "datalink.h"
#include "xlayer.h"
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#ifdef _WIN32
#include <conio.h>
#else
#define kbhit() 0
#endif

struct layer** append(struct layer *head,struct layer *tail);
static jmp_buf env;
static volatile sig_atomic_t canjmp=0;

int count(struct layer *head);

void
sig_int(int signo)
{
  if(canjmp == 1)
    longjmp(env,1); 
}

int
main(int argc, char **argv)
{
	struct layer *head,*cx;
        struct datalink dl;
	FILE *fp;
	int n,numpacs=0;
	char *m;
	canjmp = 0;


    	if( argc< 2){
		fprintf(stderr,"usage: %s <savefile> [\"bpf filter expression\"]\n",*argv);
		exit(0);
    	}

    	if(if_menu(&dl) < 0 )
		exit(1);

#ifndef _WIN32	
	signal(SIGINT,sig_int);
   	if(setjmp(env) > 0){
		fp = fopen(argv[1],"wb");
		if( fp == NULL ){
			perror(*argv);
			exit(1);
		}
  	        writelayers_pcap(head,1,dl.dl_pcap->linktype,fp);
		fclose(fp);
		printf("total %d frames received by filter.\n",numpacs);		
		rmlayers(head);	
		exit(0);
	}
	canjmp = 1;
	setuid(getuid());	
#endif

		
	if(argc >= 3){
        	filterDatalink(&dl,argv[2]);
	}
	printf("Ok.\n");

     	head = alloclayer(LT_BREAK,0);
	numpacs=0;
    	while(!kbhit()){
		

        	if( ( cx = recvlayers(&dl,&n) ) != NULL){

		   	numpacs++;
			printlayers(cx);	
			append(head,cx);			
		}
		
		
		if(n == -1){
			printf("ERROR receiving frame.\n");
		}
		
	}
	fp = fopen(argv[1],"wb");
	if(fp == NULL ){	
		perror(*argv);
		exit(1);
	}
        writelayers_pcap(head,1,dl.dl_pcap->linktype,fp);

	printf("total %d frames received by filter.\n",numpacs);
	
	fclose(fp);		

        rmlayers(head);
	
	exit(0);	

}	

struct layer* 
inithead(void){
	struct layer * m;
    m = alloclayer(LT_BREAK,0);
	return m;
}

struct layer** 
append(struct layer *head,struct layer *tail){ 
	struct layer **px; 
	px = &head; 
	while( (*px) != NULL) 
		px = &(*px)->next; 
	*px = tail; 
	return &(*px)->next; 
}

int
count(struct layer *head)
{
	struct layer **px; 
	int n = 0;
	px = &head; 
	while( (*px) != NULL){
	   n++;
		px = &(*px)->next; 
	}
	return n;
}

