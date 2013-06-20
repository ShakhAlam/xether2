#include "../include/xlayer.h"
#include "../include/datalink.h"
#ifdef _WIN32
#include <windows.h>
#endif
#include <sql.h>
#include <sqlext.h>

struct sqldes
{
	SQLHENV env;
	SQLHDBC dbc;
	SQLHSTMT stmt;
	SQLCHAR dbuf[8192*2];
    int id;
	char *dsn, *usr, *pwd;
	struct datalink dl;
};
static char sql_stmt[] = "insert into tcplog values ( ? , ?  ) ";


/* Initialize interface */
int
init_if(struct datalink *dl)
{

	return if_menu(dl);
}

void
sqlPerror(SQLHENV env, SQLHDBC dbc, SQLHSTMT stmt, const char *s)
{
    SQLCHAR sqlState[6];
    SQLINTEGER nativeErr;
    SQLCHAR errormsg[255];
    SQLSMALLINT len;
	errormsg[0] = 0;
    while( SQLError(env,dbc,stmt,sqlState,&nativeErr,errormsg,255,&len) != SQL_NO_DATA_FOUND)
    {
        fprintf(stdout,"%s: %s native[%d] SQL state[%c%c%c%c%c]\n",
                        s,errormsg,nativeErr,sqlState[0],
                        sqlState[1],sqlState[2],sqlState[3],sqlState[4]);
    }
}

/* Initialize database */
int
init_db(struct sqldes * sd)
{
 SQLRETURN ret;
 SQLAllocHandle(SQL_HANDLE_ENV,SQL_NULL_HANDLE,&sd->env);
 SQLSetEnvAttr(sd->env,SQL_ATTR_ODBC_VERSION,(SQLPOINTER)SQL_OV_ODBC3,0);
 
 SQLAllocHandle(SQL_HANDLE_DBC, sd->env, &sd->dbc);
 ret = SQLConnect(sd->dbc, sd->dsn, SQL_NTS, sd->usr, SQL_NTS, sd->pwd, SQL_NTS);
 if( ret == SQL_ERROR || ret ==  SQL_INVALID_HANDLE )
	return -1;
 SQLAllocHandle(SQL_HANDLE_STMT, sd->dbc, &sd->stmt);

 ret = SQLPrepare(sd->stmt,sql_stmt,SQL_NTS);
 if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
				sqlPerror(SQL_NULL_HANDLE,SQL_NULL_HANDLE,sd->stmt,"tcplog");
	

 sd->id = 1;
 sd->dbuf[0]=0;
 return 0;
}

/* Insert data into database */
int
ins_data(struct sqldes *sd)
{

	struct layer *head,*cx;	
	int n;
	SQLRETURN ret;
	SQLINTEGER l;
	l = SQL_NTS;

	ret = SQLBindParameter(sd->stmt,1,SQL_PARAM_INPUT,SQL_C_SLONG,SQL_INTEGER,0,0,&sd->id,0,NULL);
	if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
		sqlPerror(SQL_NULL_HANDLE,SQL_NULL_HANDLE,sd->stmt,"tcplog: binding frame id: ");

    if( ( head = recvlayers(&sd->dl,&n) ) != NULL ) {
		for(cx = head; cx != NULL ; cx = cx->next ){
			sd->id++;
			cx->sprint(sd->dbuf,sizeof(sd->dbuf),cx);
	    		ret = SQLBindParameter(sd->stmt,2,SQL_PARAM_INPUT,SQL_C_CHAR,SQL_CHAR,SQL_NTS,0,sd->dbuf,strlen(sd->dbuf),&l);  
			if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
			sqlPerror(SQL_NULL_HANDLE,SQL_NULL_HANDLE,sd->stmt,"tcplog: binding data buffer:");

			cx->print(cx);
			ret = SQLExecute(sd->stmt);
			if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
				sqlPerror(SQL_NULL_HANDLE,SQL_NULL_HANDLE,sd->stmt,"tcplog");
		
		}
        printf(".\n");
 	}
	rmlayers(head);
	return 0;
}

void
close_db(struct sqldes *sd)
{
	SQLFreeHandle(SQL_HANDLE_STMT,sd->stmt);
	SQLDisconnect(sd->dbc);
	SQLFreeHandle(SQL_HANDLE_DBC,sd->dbc);
	SQLFreeHandle(SQL_HANDLE_ENV,sd->env);
}



void
TCPLog(struct sqldes *sd)
{

	/* Initialize interface */
	if(init_if(&sd->dl) < 0 ) {
		fprintf(stderr,"Error at TCPLog:init_if()\n");
		exit(1);
	}
    filterDatalink(&sd->dl,"not arp");
	/* Initialize database */
	if(init_db(sd) < 0 ) {
		fprintf(stderr,"Error at TCPLog:init_db()\n");
		exit(1);
	}

	/* Loop */
	while(!kbhit()){
		/* Insert data into database */
		ins_data(sd);
	}
	/* close database */
	close_db(sd);
}

int
main(int argc, char **argv)
{
 struct sqldes sd;
 if(argc < 4 ) {
	fprintf(stderr,"usage: %s <dsn> <usr> <pwd>\n");
	exit(1);
 }
 sd.dsn = argv[1];
 sd.usr = argv[2];
 sd.pwd = argv[3];
 sd.id=6;
 TCPLog(&sd);
 return 0;
}
