#ifndef PROC_MAPS_H
#define PROC_MAPS_H

#include <stdlib.h>

typedef struct maps_t{
    unsigned long addr_start;
    unsigned long addr_end;
    unsigned char mode;
    unsigned char flags;
    unsigned int offset;
    unsigned int major_id;
    unsigned int minor_id;
    unsigned int inode_id;
    char* file_path;
}maps_t;

typedef struct maps_t_arr{
    size_t size;
    maps_t* maps;
}maps_t_arr;

void destroy_maps_t_arr(maps_t_arr* mapping);
maps_t_arr* parse_maps_from_pid(int pid);
maps_t_arr* parse_maps_from_path(char* path);
void print_maps_t_arr(maps_t_arr* arr);
void print_mapping(maps_t* map);

#endif

