#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <unistd.h>
#include "proc_maps.h"

int get_num_maps_entries(char* maps_file){
    int size = strlen(maps_file);
    int entries = 0;
    for(int i = 0; i<size; i++){
        if(maps_file[i] == '\n'){
            entries++;
        }
    }
    return entries;
}


#define MAPS_CHUNK_SIZE 4096
char* read_maps_file(char* filepath){
    FILE* fp = fopen(filepath,"r");

    if(fp == NULL){
        return NULL;
    }
    //maps file is weird so we cant get the filesize beforehand.
    //So we allocate a chunk and then grow that chunk as needed
    unsigned long curr_size = MAPS_CHUNK_SIZE+1;
    char* mmap_file = malloc(curr_size);
    char* cursor = mmap_file;
    if(mmap_file == NULL){
        fclose(fp);
        return NULL;
    }
    int readBytes = 0;
    while(1){
        int tmpread = fread(cursor,1,MAPS_CHUNK_SIZE,fp);
        if(tmpread < MAPS_CHUNK_SIZE){
            break;
        }
        readBytes+=tmpread;
        mmap_file = realloc(mmap_file,curr_size+MAPS_CHUNK_SIZE);
        curr_size+=MAPS_CHUNK_SIZE;
        cursor = mmap_file+readBytes;
    }
    fclose(fp);
    return mmap_file;

}

unsigned short parse_prots(char* prots){
    int ret_val = 0;
    if(strlen(prots) != 4){
        return -1;
    }
    switch(prots[0]){
        case 'r':
            ret_val |= PROT_READ;
            break;
        case '-':
            break;
        default:
            return -1;
    }
    switch(prots[1]){
        case 'w':
            ret_val |= PROT_WRITE;
            break;
        case '-':
            break;
        default:
            return -1;
    }
    switch(prots[2]){
        case 'x':
            ret_val |= PROT_EXEC;
            break;
        case '-':
            break;
        default:
            return -1;
    }
    switch(prots[3]){
        case 'p':
            ret_val |= (MAP_PRIVATE << 8);
            break;
        case 's':
            ret_val |= (MAP_SHARED << 8);
            break;
        default:
            return -1;
    }
    return ret_val;
}

maps_t_arr* parse_maps_content(char* maps_file){
    int maps_entries = get_num_maps_entries(maps_file);
    maps_t_arr* maps_arr = malloc(sizeof(maps_t_arr)+1);
    if(maps_arr == NULL){
        //fprintf(stderr,"Out of memory!\n");
        exit(1);
    }
    maps_arr->size = maps_entries;
    maps_t* maps = malloc((sizeof(maps_t)*maps_entries)+1);
    if(maps == NULL){
        //fprintf(stderr,"Out of memory!\n");
        exit(1);
    }

    unsigned long last_addr = 0;
    int i = 0;
    while(1){
        maps_t tmp_map;
        char* prots;
        int parsed_items = sscanf(
            maps_file,
            "%lx-%lx %ms %x %d:%d %d %ms\n",
            &tmp_map.addr_start,
            &tmp_map.addr_end,
            &prots,
            &tmp_map.offset,
            &tmp_map.major_id,
            &tmp_map.minor_id,
            &tmp_map.inode_id,
            &tmp_map.file_path
        );

        if(parsed_items != 8){
            break;
        }
        if(tmp_map.file_path[0] != '[' && tmp_map.file_path[0] != '/'){
            int len = strlen(tmp_map.file_path);
            memset(tmp_map.file_path,'\0',len);
        }
        
        if(last_addr > tmp_map.addr_end){
            //fprintf(stderr,"Invalid maps file, line %d: End address bigger than previous end address, current: %lu previous: %lu\n",i,tmp_map.addr_end,last_addr);
            exit(1);
        }
        unsigned short prots_short = parse_prots(prots);
        if(prots_short == -1){
            //fprintf(stderr,"Invalid maps file. Prots: %s invalid",prots);
            exit(1);
        }
        tmp_map.mode = (unsigned char)(prots_short & 0xff);
        tmp_map.flags = (unsigned char)(prots_short >> 8);
        free(prots);

        memcpy(&maps[i],&tmp_map,sizeof(maps_t));
        maps_file = strchr(maps_file,'\n')+1;
        if(maps_file == NULL){
            break;
        }


        i++;
    }
    maps_arr->maps=maps;

    return maps_arr;
}
void print_maps_t_arr(maps_t_arr* arr){
    printf("[");
    maps_t* maps = arr->maps;
    for(int i = 0; i<arr->size; i++){
        printf(
            "\nmap(\n\t0x%lx\n\t0x%lx\n\t%hhd\n\t%hhd\n\t0x%x\n\t%u\n\t%u\n\t%u\n\t%s\n),",
            maps[i].addr_start,
            maps[i].addr_end,
            maps[i].mode,
            maps[i].flags,
            maps[i].offset,
            maps[i].major_id,
            maps[i].minor_id,
            maps[i].inode_id,
            maps[i].file_path
        );
    }
}

void print_mapping(maps_t* map){
    printf(
        "\nmap(\n\t0x%lx\n\t0x%lx\n\t%hhd\n\t%hhd\n\t0x%x\n\t%u\n\t%u\n\t%u\n\t%s\n),",
        map->addr_start,
        map->addr_end,
        map->mode,
        map->flags,
        map->offset,
        map->major_id,
        map->minor_id,
        map->inode_id,
        map->file_path
    );
}

maps_t_arr* parse_maps_from_pid(int pid){
    char filepath[256] = {0};
    snprintf(filepath,256,"/proc/%d/maps",pid);
    // snprintf(filepath,256,"/proc/1/maps");

    char* maps_file = read_maps_file(filepath);
    if(maps_file == NULL){
        //fprintf(stderr,"Failed reading file %s with error: %m",filepath);
        exit(1);
    }
    maps_t_arr* mappings = parse_maps_content(maps_file);

    free(maps_file);

    return mappings;
}

maps_t_arr* parse_maps_from_path(char* path){
    char* maps_file = read_maps_file(path);
    if(maps_file == NULL){
        //fprintf(stderr, "Failed reading file %s with error: %m",path);
        exit(1);
    }
    maps_t_arr* mappings = parse_maps_content(maps_file);
    free(maps_file);
    return mappings;
}

void destroy_maps_t_arr(maps_t_arr* mapping){
    maps_t* maps = mapping->maps;
    for(int i = 0; i<mapping->size; i++){
        free(maps[i].file_path);
    }
    free(maps);
    free(mapping);
}
