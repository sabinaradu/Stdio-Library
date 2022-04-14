#include "so_stdio.h"
#include "aux.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

//functie care seteaza flagurile
int set_flags(SO_FILE *stream, const char *mode)
{
    if (strcmp(mode, "r") == 0)
        return O_RDONLY;
	else if (strcmp(mode, "r+") == 0)
        return O_RDWR;
	else if (strcmp(mode, "w") == 0)
        return O_CREAT | O_WRONLY | O_TRUNC;
	else if (strcmp(mode, "w+") == 0)
        return O_CREAT | O_RDWR | O_TRUNC;
	else if (strcmp(mode, "a") == 0)
        return O_CREAT | O_WRONLY | O_APPEND;
	else if (strcmp(mode, "a+") == 0)
        return O_CREAT | O_RDWR | O_APPEND;
	else {
        return FLAGS_ERR;
	}
}

//functie care initializeaza elementele streamului
int initialize_stream(SO_FILE *stream)
{
    stream->curr = lseek(stream->fd, 0, SEEK_CUR);
    stream->flags = 0;
    stream->buf_size = DEFAULT_BUF_SIZE;
    stream->offset = 0;
	
    stream->buffer = calloc(DEFAULT_BUF_SIZE, sizeof(char));
	if (!stream->buffer) {
		free(stream);
		return -1;
	}

    return 1;
}

//functie de creare a unui stream
SO_FILE* so_fopen(const char* pathname, const char* mode)
{
	SO_FILE *stream = (SO_FILE *) malloc(sizeof(SO_FILE));
	if (stream == NULL)
		return NULL;
	
    int flags = set_flags(stream, mode);
    if (flags == FLAGS_ERR) {
        free(stream);
        return NULL;
    }
    
	stream->fd = open(pathname, flags, 0644);
	if (stream->fd < 0) {
		free(stream);
		return NULL;
	}

	int ret = initialize_stream(stream);
    if (ret == -1) {
        stream->flags |= CREATE_ERR;
        return NULL;
    } else {
        return stream;
    }
}

//functie care inchide streamul
int so_fclose(SO_FILE* stream)
{
    
    int ret = so_fflush(stream);

    if (ret == SO_EOF) {
        free(stream->buffer);
        free(stream);
        return SO_EOF;
    } else {
        ret = close(stream->fd);
        free(stream->buffer);
        free(stream);
    }

	return ret;
}
//functie auxiliara pentru citirea unui element din fisier
int buf_read(SO_FILE* stream)
{
	int ret = read(stream->fd, stream->buffer, DEFAULT_BUF_SIZE);

	if (ret < 0) {
		
        stream->flags |= READ_ERR;
		return SO_EOF;
	
    } else if (ret >= DEFAULT_BUF_SIZE) {
        return ret;
    } 

    stream->flags |= LAST_BUF;
    stream->buf_size = ret;
	
    return ret;
}

//functie auxiliara pentru scrierea unui element din fisier
int buf_write(SO_FILE* stream)
{
	int ret = so_fflush(stream);
    if (ret < 0) {
        stream->flags |= WRITE_ERR;
        return ret;
    }

	int offset = stream->offset;
	stream->offset = 0;

	return offset;
}

//functie care da flush la buffer
int so_fflush(SO_FILE* stream)
{
	if ((stream->flags & WRITTEN)) {
		stream->flags &= ~WRITTEN;

        int bytes = 0;

        for (int offset = 0; offset != stream->offset; offset += bytes) {
            
            bytes = write(stream->fd, stream->buffer + offset, stream->offset - offset);
            if (bytes == -1) {
				stream->flags |= WRITE_ERR;
				return SO_EOF;
			}

        }
	}
	return 0;
}

//returneaza file descriptor ul
int so_fileno(SO_FILE* stream)
{
    if (stream) {
        return stream->fd;
    } else {
        return -1;
    }
}

//functie care muta cursorul
int so_fseek(SO_FILE* stream, long offset, int whence)
{    
    int ret = so_fflush(stream);
	if (ret == SO_EOF)
		return SO_EOF;

	stream->offset = 0;

	lseek(stream->fd, offset, whence);
	stream->curr = lseek(stream->fd, 0, SEEK_CUR);
	return 0;
}

//returneaza pozitia cursorului
long so_ftell(SO_FILE* stream)
{
	return stream->curr;
}

//functie care citeste fisierul
size_t so_fread(void* ptr, size_t size, size_t nmemb, SO_FILE* stream)
{
	if ((stream->flags & REACH_EOF))
		return 0;

	size_t ret, bytes_no = 0;

    for (ret = 0; ret < nmemb; ret += bytes_no / size) {
        if (!stream->offset) {
            if (buf_read(stream) == SO_EOF)
                break;
            }
        
        if ((nmemb - ret) * size < stream->buf_size - stream->offset) {
            bytes_no = (nmemb - ret) * size;
        } else {
            bytes_no = stream->buf_size - stream->offset;
        }

        memcpy(ptr + ret * size, stream->buffer + stream->offset, bytes_no);

        int diff = stream->buf_size - stream->offset;
        if (stream->flags & LAST_BUF) {
            if (bytes_no == diff) {
                stream->flags |= REACH_EOF;
            }
        }

        stream->offset += bytes_no;
        stream->offset  %= stream->buf_size;
    }

	stream->curr += ret;

	return ret;
}

//functie care scrie in fisier
size_t so_fwrite(const void* ptr, size_t size, size_t nmemb, SO_FILE* stream)
{
	size_t ret = 0, bytes_no = 0;

    for (ret = 0; ret < nmemb; ret += bytes_no / size) {

    	if (stream->offset == DEFAULT_BUF_SIZE) {
			if (buf_write(stream) == SO_EOF)
				break;
		}
    	
        int diff = stream->buf_size - stream->offset;
        if (((nmemb - ret) * size < diff)) {
            bytes_no = (nmemb - ret) * size;
        } else {
            bytes_no = stream->buf_size - stream->offset;
        }
        
    	memcpy(stream->buffer + stream->offset, ptr + ret * size, bytes_no);

    	stream->offset += bytes_no;
        stream->flags |= WRITTEN;
    }

	stream->curr += ret;

	return ret;
}

//citeste un element din fisier
int so_fgetc(SO_FILE* stream)
{
	if (stream->offset == stream->buf_size) {
        if (stream->flags & LAST_BUF) {
            stream->flags |= REACH_EOF;
		    return SO_EOF;
        }
	} else if (stream->flags & REACH_EOF)
		return SO_EOF;

	stream->offset %= stream->buf_size;
	if (!stream->offset && buf_read(stream) == SO_EOF) {
		return SO_EOF;
	}

    int ret = (int)stream->buffer[stream->offset++];
	stream->curr++;

	return ret;
}

//scrie un element in fisier
int so_fputc(int c, SO_FILE* stream)
{
	if (stream->buf_size != stream->offset || buf_write(stream) != SO_EOF) {
		stream->curr++;
	    stream->buffer[stream->offset++] = c;
	    stream->flags |= WRITTEN;

        return c;   
	} else {
        return SO_EOF;
    }

}

//intoarce 1 daca s-a ajuns la finalul fisierului
int so_feof(SO_FILE* stream)
{
    if (stream->flags & REACH_EOF)
        return 1;
    else return 0;
}

//intoarce 1 daca a avut loc o eroare pe parcursul rularii
int so_ferror(SO_FILE* stream)
{
    if ((stream->flags & (WRITE_ERR | READ_ERR)) == 0) {
        return 0;
    } else {
        return SO_EOF;
    }
}

SO_FILE* so_popen(const char* command, const char* type)
{
	return NULL;
}

int so_pclose(SO_FILE* stream)
{
	return 0;
}