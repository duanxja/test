/* command "defrule" */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "utmlog.h"
#include "public.h"
#include "defrule.h"

#define MYSQLDB_EVENT "snort_set"
#define MYSQLDB_IDS_DEFAULT "ids_default"
#define MYSQLDB_IDS_DEFAULT_TABLE "ids_default"  // 20230309

char interface[20];
MYSQL global_conn_name;
int global_debug=0;
int opendb_sql(char *database)
{
	int ret;
	ret=pub_connect_mysql(&global_conn_name,database);
	if(ret !=0 )
	{
		utm_log_write(DEBUG_LOG,LOG_ERR,"open database %s failed !!!!!\n",database);
		return -1;
	}
	return ret;
}
void closedb_sql(void)
{
	pub_close_mysql(&global_conn_name);
}
static int exec_mysql(char* sql)
{
	int result=0;
	result=pub_mysql_exec(&global_conn_name,sql);
	if(result <0){
		printf("database failed %s:\n%s:%d error=%s \n ",MYSQLDB_EVENT,__FILE__,__LINE__,mysql_error(&global_conn_name));
	}
	return result;
}

/* print help information */
int show_usage()
{
	printf("\n\n");
	printf("Usage: \n\n");
	printf("defrule import <filename> <interface>\n\n"
               "defrule export <filename>\n\n"
	       "defrule delete <id>\n\n"
	       "defrule --help\n\n"
               );

        return 0;
}
void recover(char *file,char* cmd)
{
	FILE *fin,*fout;
	char str[1000];
	fin=fopen(file,"r");
	fout=fopen("tmp.txt","w");
	if(fin==NULL || fout==NULL){
		utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Open the file failure...",__FILE__,__LINE__);
		return;
	}
	
	while(!feof(fin)&&fgets(str,1000,fin))
	{
		if(!strstr(str,cmd))
		{
			fputs(str,fout);
		}
	}
	fclose(fin);
	fclose(fout);
	remove(file);
	rename("tmp.txt",file);
	return;
}
int check_valid(char* filename)
{
	char add[256],cmd[256],buff[512];
	FILE* fp,*p;
	int flag=-1;
	sprintf(add,"include %s\n",filename);
	if(!(fp= fopen("/etc/snort/snort.conf","a+")))
		return 0;
	fputs(add,fp);
	fclose(fp);
	sprintf(cmd, "snort -i %s -c /etc/snort/snort.conf -A fast --ifruleok 2>&1",interface);
	p=popen(cmd, "r");
	memset(buff,0,sizeof(buff));
	if(global_debug){
		printf("%s %d cmd =%s\n",__FUNCTION__,__LINE__,cmd);
	}
	while(fgets(buff,512,p))
	{
		/* rules wrong */
		if(strstr(buff,"ERROR:") && strstr(buff,filename))
		{
			//printf("%s",buff);
			flag=0;
			utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :%s",__FILE__,__LINE__,buff);
			break;
		}
		/* rules right */
		else if(strstr(buff,"Commencing packet"))
		{
			flag=1;
			if(global_debug){
				printf("%s %d quit flag=%d \n",__FUNCTION__,__LINE__,flag);
			}
			break;
		}
	}
	pclose(p);
	if(global_debug){
		printf("%s %d over !!! quit flag=%d \n",__FUNCTION__,__LINE__,flag);
	}
	recover("/etc/snort/snort.conf",add);
	if(flag==0) {
		return 0;
	}
	else if(flag==1)
	{
		return 1;
	}
	return 1;
}
#if 1
// 0--find -1 nofind 
int find_max_id(int *id)
{
	char sql[512];
	int result=0;
	MYSQL_ROW row_p;
	MYSQL_RES *result_p;
	memset(sql,0x00,sizeof(sql));
	
	result=opendb_sql(MYSQLDB_IDS_DEFAULT);
	if(result<0){
		printf("Can't open database : %s ???\n",MYSQLDB_IDS_DEFAULT);
		return result;
	}
	sprintf(sql,"select MAX(id) from ids_default");
	result=pub_mysql_exec(&global_conn_name,sql);
	if(global_debug)
		printf("%s %d sql=%s result=%d\n",__FUNCTION__,__LINE__,sql,result);
	if(result <0){
		printf("database failed %s:    %s:%d",MYSQLDB_IDS_DEFAULT,__FILE__,__LINE__);
		closedb_sql();
		return result;
	}
	if(global_debug)
		printf("%s %d sql=%s result=%d\n",__FUNCTION__,__LINE__,sql,result);
	result_p=mysql_use_result(&global_conn_name);
	if(!result_p){
		printf("mysql_use error!\n");
		closedb_sql();
		return -1;
	}
	if(row_p=mysql_fetch_row(result_p)){
		*id=row_p[0];
		result=0;
	}else
		result=-1;
	mysql_free_result(result_p);
	closedb_sql();
	return result;
}

int file_2_db(void)
{
	char sql[2048];
	int result;
	FILE *fp;
	FILE *fpw;
	char str[1000];
	char cmd[2048];
	int i=0;
	int id=1; // 20230313
	result = opendb_sql(MYSQLDB_EVENT);
	if(result !=0){
		utm_log_write(DEBUG_LOG, LOG_INFO, "Ambria %s %d Error: database %s",__FILE__,__LINE__,MYSQLDB_EVENT);
        return 0;
    }
	result = exec_mysql("delete from usr_rules");
    if (result !=0){
		closedb_sql();
        utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Delete error!",__FILE__,__LINE__);
        return 0;
    }
	closedb_sql();
	//
	fp=fopen("/etc/snort/rules/custom.rules","r");
    if(fp==NULL){
       utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Open the file failure.. custom.rules.",__FILE__,__LINE__);
	   return 0;
	}
    while(!feof(fp)&& fgets(str,1000,fp)){
		if(strcmp(str,"\n")){
			if(!strstr(str,"alert"))
				continue;
			str[strlen(str)-1]='\0';
			fpw=fopen("/tmp/tmp.sql","w+");
			if(fpw==NULL){
			   utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Open the file failure.. custom.rules.",__FILE__,__LINE__);
			   return 0;
			}
			fprintf(fpw,"insert into usr_rules values (%d,'%s');\n",id++,str); // 20230309
			snprintf(cmd,2048,"mysql -u root -pseatech@123 snort_set </tmp/tmp.sql");
			if(global_debug){
				printf("%s %d  i=%d \n",__FUNCTION__,__LINE__,i);
			}
			fclose(fpw);
			system(cmd);
		}
		i++;
		memset(sql,0,2048);
		memset(cmd,0,2048);
    }
    fclose(fp);
	return 1;
}

#endif
int db_2_file(void)
{	
	MYSQL_ROW row_p;
	MYSQL_RES *result_p;
	char sql[500]={0};
	int result=0;
	FILE* file = NULL;

	opendb_sql(MYSQLDB_EVENT);
	memset(sql,0,512);
	strcpy(sql,"select usr_rule from  usr_rules");
	result=pub_mysql_exec(&global_conn_name,sql);
	if(result <0){
		printf("database failed %s:\n%s:%d",MYSQLDB_EVENT,__FILE__,__LINE__);
		closedb_sql();
		exit(1);
	}
	result_p=mysql_use_result(&global_conn_name);
	if(!result_p){
		printf("mysql_use error!\n");
		closedb_sql();
		exit(1);
	}
	if((file = fopen("/etc/snort/rules/custom.rules", "w+")) == NULL)
	{
			fprintf(stderr, "Open %s error!\n", "custom.rules");
			return -1;
	}
	while((row_p=mysql_fetch_row(result_p)) != NULL){
		if(fputs(row_p[0], file) == EOF){
			fprintf(stderr, "Write %s error.", "custom.rules");
			break;
		}
		else{
			fputs("\n", file);
		}
	}
	fclose(file);
	mysql_free_result(result_p);	
	closedb_sql();
	return 1;
}

int add_rules(char* filename)
{
	FILE *fin,*fout;
	char str[3000];
	if(global_debug)
		printf("%s %d  upload filename=%s\n",__FILE__,__LINE__,filename); 
	fin=fopen(filename,"r");
	fout=fopen("/etc/snort/rules/custom.rules","a+");
	if(fin==NULL || fout==NULL){
		if(global_debug)
			printf("Ambria %s %d :Open the file failure...",__FILE__,__LINE__);	
		utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Open the file failure...",__FILE__,__LINE__);
		return 0;
	}
	while(!feof(fin)&&fgets(str,3000,fin))
	{
		//if(!strstr(str,"#") &&  strcmp(str,"\n"))  no need ,directroy copy ok 20221208
		if(strstr(str,"alert"))
		{
			if(global_debug)
				printf("%s %d str=%s\n",__FILE__,__LINE__,str); 
			fputs(str,fout);
		}
	}
	fclose(fin);
	fclose(fout);
	return 1;

}
void strTrim(char **pStr)  
{  
	char *index;
	index=*pStr+strlen(*pStr)-1;
	while(*index==' ') index--;
	*(index+1)='\0';
	index=*pStr;
	while(*index==' ' || *index==':')index++;
	*pStr=index;
}	
char* substring(char*str,char* start, char* end)
{
	char *buffer =(char*)malloc(80);
	char *first,*last;
	int n;
	first=strstr(str,start);

	if(!first)return NULL;
	last=strstr(first,end);
	n=last-first;
	memset(buffer,0,80);
	strncpy(buffer,first+strlen(start)+1,n-strlen(start)-1);
	strTrim(&buffer);
	return buffer;
}
#if 0
int check_classtype(char* filename)
{

	char** classtype=(char**)malloc(100*sizeof(char*));
	int i=0;
	int len;
	
	FILE *fp;
        char str[3000];
	char *temp;

	if(global_debug){
		printf("%s %d  filename=%s\n",__FUNCTION__,__LINE__,filename);
	}
		memset(classtype,0,100*sizeof(char*));
        fp=fopen("/etc/snort/classification.config","r");
        if(fp==NULL){
		utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Open the file failure...",__FILE__,__LINE__);
                return 0;
        }
        while(!feof(fp)&&fgets(str,3000,fp))
        {
                if(!strstr(str,"#") && strcmp(str,"\n"))
                {
			classtype[i++]=substring(str,"classification",",");
                }
        }
	len=i;
/*
	for(i=0;i<len;i++)
		printf("i=%d	%s\n",i,classtype[i]);
*/

	fclose(fp);
        fp=fopen(filename,"r");
        if(fp==NULL){
		utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Open the file failure...",__FILE__,__LINE__);
                return 0;
        }
	while(!feof(fp)&&fgets(str,3000,fp))
	{
		if(!strstr(str,"#") && strcmp(str,"\n"))
		{
			if(global_debug){
				printf("%s %d  str=%s\n",__FUNCTION__,__LINE__,str);
			}

			temp=substring(str,"classtype",";");	

			
			if(global_debug){
				printf("%s %d  temp=%s\n",__FUNCTION__,__LINE__,temp);
			}
			if(!temp)
				continue;
			for(i=0;i<len;i++)
			{
				if(!strcmp(temp,classtype[i])){
					if(global_debug){
						printf("%s %d find i=%d  classtype[i]=%s\n",__FUNCTION__,__LINE__,i,classtype[i]);
					}
					break;
				}
			}
			if(i==len)
			{
				fclose(fp);
				utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d : classtype %s can't find!",__FILE__,__LINE__,temp);
				return 0;
			}
		}
	}
	fclose(fp);
	return 1;
}
#else
// 0--find -1 nofind 
int find_class_type(char *virus)
{
	char sql[512];
	int result=0;
	MYSQL_ROW row_p;
	MYSQL_RES *result_p;
	memset(sql,0x00,sizeof(sql));
	
	//
	if(global_debug)
		printf("%s %d read check virus=%s\n",__FUNCTION__,__LINE__,virus);
	//
	result=opendb_sql(MYSQLDB_IDS_DEFAULT);
	if(result<0){
		printf("Can't open database : %s ???\n",MYSQLDB_IDS_DEFAULT);
		return result;
	}
	//
	if(global_debug)
		printf("%s %d read check virus=%s\n",__FUNCTION__,__LINE__,virus);
	//
	//读取数据
	//sprintf(sql,"select childname,desc,alert from %s;","classification");
	sprintf(sql,"select name from ids_default where name='%s';",virus);
	result=pub_mysql_exec(&global_conn_name,sql);
	if(global_debug)
		printf("%s %d sql=%s result=%d\n",__FUNCTION__,__LINE__,sql,result);
	if(result <0){
		printf("database failed %s:    %s:%d",MYSQLDB_IDS_DEFAULT,__FILE__,__LINE__);
		closedb_sql();
		return result;
	}
	if(global_debug)
		printf("%s %d sql=%s result=%d\n",__FUNCTION__,__LINE__,sql,result);
	result_p=mysql_use_result(&global_conn_name);
	if(!result_p){
		printf("mysql_use error!\n");
		closedb_sql();
		return -1;
	}
	if(row_p=mysql_fetch_row(result_p)){
		result=0;
	}else
		result=-1;
	mysql_free_result(result_p);
	closedb_sql();
	if(global_debug)
		printf("%s %d find virus=%s result=%d(0--success)\n",__FUNCTION__,__LINE__,virus,result);
	return result;
}
int check_classtype(char* filename)
{

	char** classtype=(char**)malloc(100*sizeof(char*));
	int i=0;
	int len;
	int result=0;
	FILE *fp;
        char str[3000];
	char *temp;

	if(global_debug){
		printf("%s %d  filename=%s\n",__FUNCTION__,__LINE__,filename);
	}
    fp=fopen(filename,"r");
     if(fp==NULL){
		utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Open the file failure...",__FILE__,__LINE__);
               return 0;
    }
	while(!feof(fp)&&fgets(str,3000,fp))
	{
		if(!strstr(str,"#") && strcmp(str,"\n"))
		{
			if(global_debug){
				printf("%s %d  str=%s\n",__FUNCTION__,__LINE__,str);
			}

			temp=substring(str,"classtype",";");	

			
			if(global_debug){
				printf("%s %d  temp=%s\n",__FUNCTION__,__LINE__,temp);
			}
			if(!temp)
				continue;
			result=find_class_type(temp);
			if(result<0)
			{
				fclose(fp);
				utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d : classtype %s can't find!",__FILE__,__LINE__,temp);
				return 0;
			}
		}
	}
	fclose(fp);
	return 1;
}

#endif 
int del_rule(int id)
{
	char sql[500];
	int result;

	result = opendb_sql(MYSQLDB_EVENT);
	if(result !=0){
	   utm_log_write(DEBUG_LOG, LOG_INFO, "Ambria %s %d Error: database %s",__FILE__,__LINE__,MYSQLDB_EVENT);
	   return 0;
	}
	sprintf(sql,"delete from usr_rules where id=%d",id);
	result = exec_mysql(sql);
	if (result !=0){
	   closedb_sql();
	   utm_log_write(DEBUG_LOG, LOG_ERR, "Ambria %s %d :Delete error!",__FILE__,__LINE__);
	   return 0;
	}
	closedb_sql();
	db_2_file();
	file_2_db();
    return 1;
}
int main(int argc, char** argv)
{
	int id;
	char filename[100];
	int success=0;
	if((argc ==5) || (argc ==4 && !strcmp(argv[1],"import")) || (argc==3 && !strcmp(argv[1],"export")) || (argc==3 && !strcmp(argv[1],"delete")))
	{
		/* import */
		if((argc==5 && !strcmp(argv[1],"import")) || (argc==4 && !strcmp(argv[1],"import")))
		{
			if(argc == 5)
				global_debug=1;
			strcpy(filename,argv[2]);
			strcpy(interface,argv[3]);
			sprintf(filename, "/tmp/upload/%s",argv[2]);//拼接自定义规则存放路径
			if(global_debug){
				printf("%s %d upload file =%s\n",__FUNCTION__,__LINE__,filename);
			}
			/* rules file invalid, return 1*/
			if(!(success=check_valid(filename))) 
				return 1;

			/* unknowned classtype */
			if(!(success=check_classtype(filename))){
				if(global_debug){
					printf("%s %d have error virus =%s\n",__FUNCTION__,__LINE__,filename);
				}
				return 2;
			}

			if(global_debug){
				printf("%s %d ready to write add_rules =%s\n",__FUNCTION__,__LINE__,filename);
			}

			/* add rules failed , return 2*/
			if(!(success=add_rules(filename)))  
				return 3;
			if(!(success=file_2_db()))
				return 4;
		}
		/* export */
		else if(!strcmp(argv[1],"export"))
		{
			char cmd[100];
			sprintf(cmd, "cp -rf /etc/snort/rules/custom.rules /tmp/download/%s",argv[2]);
			system(cmd);
		}
		else if(!strcmp(argv[1],"delete"))
		/*delete*/
		{
			id=atoi(argv[2]);
			if(!(success=del_rule(id)))
				return 5;	
		}

        }
        else
        {
		show_usage();
		return -1;
        }
	utm_log_write(DEBUG_LOG, LOG_INFO, "Ambria %s end",__FILE__);
	return 0;
}
