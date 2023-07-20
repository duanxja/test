#ifdef __DEFRULE_H__
extern int show_usage();
extern int check_valid(char *filename);
extern int add_rules(char *filename);
extern void recover(char *file,char* cmd);
extern int check_classtype(char* filename);
extern char* substring(char*str,char* start, char* end);
extern void strTrim(char **pStr);
extern int file_2_db(void);
extern int db_2_file(void);
extern int del_rule(int id);
#endif 
