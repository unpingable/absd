#include <stdio.h>
#include <string.h>
extern char **environ;
int main(int argc, char **argv, char **envp) {
    printf("argc=%d\n", argc);
    for (int i = 0; i < argc; i++) printf("argv[%d]=[%s] len=%zu\n", i, argv[i], strlen(argv[i]));
    if (argv[argc] != NULL) printf("argv not NULL-terminated\n");
    if (envp != environ) printf("environ != envp\n");
    int n = 0;
    for (char **e = envp; *e; e++, n++) printf("env[%d]=[%s]\n", n, *e);
    printf("envc=%d\n", n);
    return 0;
}
