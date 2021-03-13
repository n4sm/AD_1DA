#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int nb = 10;

int main(){
	char test = 'c';
	int foo = 0;
	printf("Hello World\n");
	printf("%d", nb);

	char *a = malloc(256);

	*a = NULL;
	memset(a, '\0', 256);

	free(a);
	return 0;
}
