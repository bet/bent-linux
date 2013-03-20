#include <stdio.h>

int main(int argc, char **argv) {
    unsigned char buff[8192];
    char hist[256];
    int i;

    while (read(0, buff, 8192) > 0) {
	for (i=0; i<8192; i++) {
	    hist[buff[i]]++;
	}
    }
    for (i = 0; i<256; i++) {
    	if (hist[i] > 0) {
	    printf("%2x %d\n", i, hist[i]);
	}
    }
}
