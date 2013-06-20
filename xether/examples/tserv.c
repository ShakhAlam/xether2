#include <winsock.h>
#include <stdlib.h>
#include <stdio.h>

int
main(int argc, char **argv)

{
  struct sockaddr_in ina,cli;
  WSADATA wData;
  SOCKET s,c;
  char buf[1024];
  int slen = 0,nrecv = 0;

  WSAStartup(MAKEWORD(1,1),&wData);

  memset(&ina,0,sizeof(ina));
  ina.sin_family = AF_INET;
  ina.sin_addr.s_addr = htonl(INADDR_ANY);
  ina.sin_port = htons(110);
  if( (  s =  socket(AF_INET,SOCK_STREAM,0) ) == SOCKET_ERROR ) {
    perror(*argv);
    exit(1);
  }
  if( bind(s,(struct sockaddr*)&ina,sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
    fprintf(stderr,"bind ERROR\n");
    exit(1);
  }

  if( listen(s,10) < 0 ){
    fprintf(stderr,"listen ERROR\n");
    exit(1);

  }

  while(1){
    slen = sizeof(struct sockaddr_in);
    if( ( c = accept(s,(struct sockaddr*)&cli,&slen) ) == SOCKET_ERROR) {
        printf("accept error\n");
        continue;
    }
    while( ( nrecv = recv(c,buf,sizeof(buf)-1,0 ) ) > 0 ){
        buf[nrecv]=0;
        printf("%s",buf);
    }
   closesocket(c);
  }
  closesocket(s);
  WSACleanup();
  return 0;
}


