#include <stdlib.h>


//definitiile flag urilor
#define WRITTEN		1		// daca exista data in buffer care nu a fost flushuita
#define REACH_EOF	2		// daca cursorul a ajuns la finalul fisierului
#define LAST_BUF	4		// daca EOF este in acel buffer
#define WRITE_ERR	8		// eroare la scriere in fisier
#define READ_ERR	16		// eroare la citire in fisier
#define CREATE_ERR  32		//eroare la crearea stream-ului
#define FLAGS_ERR   -1		//eroare la setarea flagurilor

#define DEFAULT_BUF_SIZE 4096

struct _so_file {
	int fd;					// File Descriptor
	ssize_t curr;			// pozitia cursorului in fisier

	char* buffer;			// Buffer pt buffered IO
	ssize_t offset;			// primul element nescris in buffer
	ssize_t buf_size;		// dimensiunea maxima a bufferului

	int flags;				//flaguri
};