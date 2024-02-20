#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <sys/wait.h>
#include <ctype.h>
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20

#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

void print_usage() {
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
    exit(0);
}

void print_file_system_info(BootEntry *boot_entry) {
    printf("Number of FATs = %d\n", boot_entry->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", boot_entry->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", boot_entry->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", boot_entry->BPB_RsvdSecCnt);
}

unsigned int get_starting_cluster(unsigned short hi, unsigned short lo){
    return ((unsigned int)hi << 16) | lo;
}

int is_file_to_recover(unsigned char* DIR_Name, char* rec_filename){
    
    char filename[9];
    memcpy(filename, DIR_Name, 8);
    filename[8] = '\0';
    char *src = filename;
    char *dest = filename;
    while(*src){
        if(!isspace(*src)){
            *dest++ = *src;
        }
        src++;
    }
    *dest = '\0';

    char ext[4];
    memcpy(ext, DIR_Name + 8, 3);
    ext[3] = '\0';
    char *src2 = ext;
    char *dest2 = ext;
    while(*src2){
        if(!isspace(*src2)){
            *dest2++ = *src2;
        }
        src2++;
    }
    *dest2 = '\0';

    int total_filename_len = strlen(filename) + strlen(ext) + 1;

    if(ext[0] != '\0'){
        total_filename_len++;
        char total_filename[total_filename_len];
        strcpy(total_filename, filename);
        strcat(total_filename, ".");
        strcat(total_filename, ext);
        total_filename[strlen(total_filename)] = '\0';
        if (strlen(total_filename) == strlen(rec_filename) && strncmp(total_filename+1, rec_filename+1, strlen(total_filename)-1) == 0){
            return 1;
        }
    }
    else{
        char total_filename[total_filename_len];
        strcpy(total_filename, filename);
        total_filename[strlen(total_filename)] = '\0';
        if (strlen(total_filename) == strlen(rec_filename) && strncmp(total_filename+1, rec_filename+1, strlen(total_filename)-1) == 0){
            return 1;
        }
    }

    return 0;
}

int get_num_clusters(int file_size, int bytes_per_cluster){
    int num_clusters = (file_size + 1) / bytes_per_cluster;
    num_clusters += (file_size % bytes_per_cluster == 0) ? 0 : 1;
    return num_clusters;
}

void update_fat_cont(int* fat_to_update, unsigned int starting_cluster, int num_clusters){
    for(int i=0; i<num_clusters-1; i++){
        fat_to_update[starting_cluster] = starting_cluster + 1;
        starting_cluster++;
    }
    fat_to_update[starting_cluster] = 0x0fffffff;
}

void recover_contiguous_file(DirEntry* dir_entry, int index, char* filename, char* diskptr, int fat_start_offset, int num_fats, int bytes_per_fat, int bytes_per_cluster){
    dir_entry[index].DIR_Name[0] = filename[0];
    unsigned int starting_cluster = get_starting_cluster(dir_entry[index].DIR_FstClusHI, dir_entry[index].DIR_FstClusLO);
    int num_clusters = get_num_clusters(dir_entry[index].DIR_FileSize, bytes_per_cluster);

    if(starting_cluster != 0){
        int *fat_to_update;
        for (int i = 0; i < num_fats; i++){
            fat_to_update = (int *) (diskptr + fat_start_offset + (i * bytes_per_fat));
            update_fat_cont(fat_to_update, starting_cluster, num_clusters);
        }
    }
}

void recover_non_contiguous_file(DirEntry* dir_entry, int index, char* filename, char* diskptr, int fat_start_offset, int num_fats, int bytes_per_fat, int num_clusters, int starting_cluster, int a, int b, int c, int d){
    // update filename
    dir_entry[index].DIR_Name[0] = filename[0];

    // update FAT
    if(starting_cluster != 0){
        int *fat_to_update;
        for (int i = 0; i < num_fats; i++){
            fat_to_update = (int *) (diskptr + fat_start_offset + (i * bytes_per_fat));
            if(num_clusters == 1){
                fat_to_update[starting_cluster] = 0x0fffffff;
            }
            if(num_clusters == 2){
                fat_to_update[starting_cluster] = a;
                fat_to_update[a] = 0x0fffffff;
            }
            if(num_clusters == 3){
                fat_to_update[starting_cluster] = a;
                fat_to_update[a] = b;
                fat_to_update[b] = 0x0fffffff;
            }
            if(num_clusters == 4){
                fat_to_update[starting_cluster] = a;
                fat_to_update[a] = b;
                fat_to_update[b] = c;
                fat_to_update[c] = 0x0fffffff;
            }
            if(num_clusters == 5){
                fat_to_update[starting_cluster] = a;
                fat_to_update[a] = b;
                fat_to_update[b] = c;
                fat_to_update[c] = d;
                fat_to_update[d] = 0x0fffffff;
            }
        }
    }
}

int check_empty_file_sha1(unsigned char* user_sha1){
    char *empty_file_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    unsigned char empty_file_hash[SHA_DIGEST_LENGTH];

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sscanf(empty_file_sha1 + (2 * i), "%2hhx", &empty_file_hash[i]);
    }

    if (memcmp(empty_file_hash, user_sha1, SHA_DIGEST_LENGTH) == 0) {
        return 1;
    } else {
        return 0;
    }    
}

int is_sha1_noncont_match_and_recovered(DirEntry* dir_entry, int index, char* sha1, char* disk_ptr, int* fat, int fat_start_offset, int num_fats, int bytes_per_fat, int bytes_per_cluster, char* filename){
    unsigned int starting_cluster = get_starting_cluster(dir_entry[index].DIR_FstClusHI, dir_entry[index].DIR_FstClusLO);
    
    // convert user input sha1 to hex
    unsigned char user_sha1[SHA_DIGEST_LENGTH];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sscanf(sha1 + (2 * i), "%2hhx", &user_sha1[i]);
    }

    // handle empty file
    if(starting_cluster == 0){
        if(check_empty_file_sha1(user_sha1)){
            recover_non_contiguous_file(dir_entry, index, filename, disk_ptr, fat_start_offset, num_fats, bytes_per_fat, 0, 0, 0, 0, 0, 0);
            return 1;
        } else {
            return 0;
        }
    }
    
    int file_size = dir_entry[index].DIR_FileSize;
    int num_clusters = get_num_clusters(file_size, bytes_per_cluster);
    unsigned char *file_data = (unsigned char *) malloc(file_size);
    
    int read_cluster_offset = fat_start_offset + (num_fats * bytes_per_fat) + ((starting_cluster - 2) * bytes_per_cluster);


    // get data for first cluster
    if(num_clusters == 1){
        memcpy(file_data, disk_ptr + read_cluster_offset, file_size % bytes_per_cluster == 0 ? bytes_per_cluster : file_size % bytes_per_cluster);
    } else {
        memcpy(file_data, disk_ptr + read_cluster_offset, bytes_per_cluster);
    }
    
    unsigned char file_sha1[SHA_DIGEST_LENGTH];
    int num_clus_to_find = num_clusters - 1;

    if(num_clus_to_find > 0){
        int to_find_clus[4] = {0};
        for(int j=0; j<num_clus_to_find; j++){
            to_find_clus[j] = 1;
        }

        for(int a=2; a<22; a++){
            if(to_find_clus[0]==0){
                break;
            } else if(fat[a] != 0 || a == (int)starting_cluster){
                continue;
            }

            for(int b=2; b<22; b++){
                if(to_find_clus[1]==0){
                    b = 23;
                } else if(fat[b] != 0 || b == (int)starting_cluster || a == b){
                    continue;
                }

                for(int c=2; c<22; c++){
                    if(to_find_clus[2]==0){
                        c = 23;
                    } else if(fat[c] != 0 || c == (int)starting_cluster || a == c || b == c){
                        continue;
                    }

                    for(int d=2; d<22; d++){
                        if(to_find_clus[3]==0){
                            d = 23;
                        } else if(fat[d] != 0 || d == (int)starting_cluster || a == d || b == d || c == d){
                            continue;
                        }
                        
                        int bytes_to_copy = 0;
                        //get data for a
                        read_cluster_offset = fat_start_offset + (num_fats * bytes_per_fat) + ((a - 2) * bytes_per_cluster);
                        if(b==23){
                            bytes_to_copy = file_size % bytes_per_cluster == 0 ? bytes_per_cluster : file_size % bytes_per_cluster;
                        } else {
                            bytes_to_copy = bytes_per_cluster;
                        }
                        memcpy(file_data + bytes_per_cluster, disk_ptr + read_cluster_offset, bytes_to_copy);

                        //get data for b if needed
                        if(b != 23){
                            if(c==23){
                                bytes_to_copy = file_size % bytes_per_cluster == 0 ? bytes_per_cluster : file_size % bytes_per_cluster;
                            } else {
                                bytes_to_copy = bytes_per_cluster;
                            }
                            read_cluster_offset = fat_start_offset + (num_fats * bytes_per_fat) + ((b - 2) * bytes_per_cluster);
                            memcpy(file_data + (bytes_per_cluster * 2), disk_ptr + read_cluster_offset, bytes_to_copy);
                        }

                        //get data for c if needed
                        if(c != 23){
                            if(d==23){
                                bytes_to_copy = file_size % bytes_per_cluster == 0 ? bytes_per_cluster : file_size % bytes_per_cluster;
                            } else {
                                bytes_to_copy = bytes_per_cluster;
                            }
                            read_cluster_offset = fat_start_offset + (num_fats * bytes_per_fat) + ((c - 2) * bytes_per_cluster);
                            memcpy(file_data + (bytes_per_cluster * 3), disk_ptr + read_cluster_offset, bytes_to_copy);
                        }

                        //get data for d if needed
                        if(d != 23){
                            bytes_to_copy = file_size % bytes_per_cluster == 0 ? bytes_per_cluster : file_size % bytes_per_cluster;
                            read_cluster_offset = fat_start_offset + (num_fats * bytes_per_fat) + ((d - 2) * bytes_per_cluster);
                            memcpy(file_data + (bytes_per_cluster * 4), disk_ptr + read_cluster_offset, bytes_to_copy);
                        }

                        SHA1((const unsigned char *) file_data, file_size, file_sha1);
                        if (memcmp(file_sha1, user_sha1, SHA_DIGEST_LENGTH) == 0) {
                            recover_non_contiguous_file(dir_entry, index, filename, disk_ptr, fat_start_offset, num_fats, bytes_per_fat, num_clusters, starting_cluster, a, b, c, d);
                            free(file_data);
                            return 1;
                        }
                    }
                }
            }
        }
    }
    else {
        SHA1((const unsigned char *) file_data, file_size, file_sha1);
        if (memcmp(file_sha1, user_sha1, SHA_DIGEST_LENGTH) == 0) {
            recover_non_contiguous_file(dir_entry, index, filename, disk_ptr, fat_start_offset, num_fats, bytes_per_fat, num_clusters, starting_cluster, 0, 0, 0, 0);
            free(file_data);
            return 1;
        }
    }

    free(file_data);
    return 0;
}

int is_sha1_match(DirEntry dir_entry, char* sha1, char* disk_ptr, int fat_start_offset, int num_fats, int bytes_per_fat, int bytes_per_cluster){
    unsigned int starting_cluster = get_starting_cluster(dir_entry.DIR_FstClusHI, dir_entry.DIR_FstClusLO);
    
    // convert user input sha1 to hex
    unsigned char user_sha1[SHA_DIGEST_LENGTH];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sscanf(sha1 + (2 * i), "%2hhx", &user_sha1[i]);
    }

    // handle empty file
    if(starting_cluster == 0){
        return check_empty_file_sha1(user_sha1);
    }
    
    int file_size = dir_entry.DIR_FileSize;
    int num_clusters = get_num_clusters(file_size, bytes_per_cluster);
    unsigned char *file_data = (unsigned char *) malloc(file_size);
    
    int read_cluster_offset = fat_start_offset + (num_fats * bytes_per_fat) + ((starting_cluster - 2) * bytes_per_cluster);

    int i;
    for(i=0; i<num_clusters-1; i++){
        memcpy(file_data + (i * bytes_per_cluster), disk_ptr + read_cluster_offset, bytes_per_cluster);
        read_cluster_offset += bytes_per_cluster;
    }
    memcpy(
        file_data + (i * bytes_per_cluster), 
        disk_ptr + read_cluster_offset, 
        file_size % bytes_per_cluster == 0 ? bytes_per_cluster : file_size % bytes_per_cluster
        );

    unsigned char file_sha1[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *) file_data, file_size, file_sha1);
    
    if (memcmp(file_sha1, user_sha1, SHA_DIGEST_LENGTH) == 0) {
        free(file_data);
        return 1;
    } else {
        free(file_data);
        return 0;
    }    
}

void print_directory_entry(DirEntry dir_entry) {
    if(dir_entry.DIR_Attr == 0x10){
        char dirname[12];
        memcpy(dirname, dir_entry.DIR_Name, 11);
        dirname[11] = '\0';
        char *src = dirname;
        char *dest = dirname;
        while(*src){
            if(!isspace(*src)){
                *dest++ = *src;
            }
            src++;
        }
        *dest = '\0';
        unsigned int starting_cluster = get_starting_cluster(dir_entry.DIR_FstClusHI, dir_entry.DIR_FstClusLO);
        printf("%s/ (starting cluster = %d)\n", dirname, starting_cluster);
    }
    else {
        char filename[9];
        memcpy(filename, dir_entry.DIR_Name, 8);
        filename[8] = '\0';
        char *src = filename;
        char *dest = filename;
        while(*src){
            if(!isspace(*src)){
                *dest++ = *src;
            }
            src++;
        }
        *dest = '\0';

        char ext[4];
        memcpy(ext, dir_entry.DIR_Name + 8, 3);
        ext[3] = '\0';
        char *src2 = ext;
        char *dest2 = ext;
        while(*src2){
            if(!isspace(*src2)){
                *dest2++ = *src2;
            }
            src2++;
        }
        *dest2 = '\0';

        int file_size = dir_entry.DIR_FileSize;

        if(file_size != 0){
            unsigned int starting_cluster = get_starting_cluster(dir_entry.DIR_FstClusHI, dir_entry.DIR_FstClusLO);
            if(ext[0] != '\0'){
                printf("%s.%s (size = %d, starting cluster = %d)\n", filename, ext, file_size, starting_cluster);
            }
            else{
                printf("%s (size = %d, starting cluster = %d)\n", filename, file_size, starting_cluster);
            }
            
        }
        else{
            if(ext[0] != '\0'){
                printf("%s.%s (size = %d)\n", filename, ext, file_size);
            }
            else{
                printf("%s (size = %d)\n", filename, file_size);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    int opt;
    char *filename = NULL, *sha1 = NULL, *disk_name = NULL;
    int opt_r = 0, opt_R = 0, opt_i = 0, opt_l=0;

    if (argc < 3 || argc > 6) {
        print_usage();
    }

    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1) {
        switch (opt) {
            case 'i':
                if (argc != 3) {
                    print_usage();
                }
                opt_i=1;
                break;
            case 'l':
                if (argc != 3) {
                    print_usage();
                }
                opt_l=1;
                break;
            case 'r':
                if (opt_R || (argc != 4 && argc != 6)) {
                    print_usage();
                }
                opt_r = 1;
                filename = optarg;
                break;
            case 'R':
                if (opt_r || argc != 6) {
                    print_usage();
                }
                opt_R = 1;
                filename = optarg;
                break;
            case 's':
                if (argc != 6) {
                    print_usage();
                }
                sha1 = optarg;
                break;
            default:
                print_usage();
        }
    }

    if ((opt_r || opt_R) && filename == NULL) {
        print_usage();
    }

    if (opt_R && sha1 == NULL) {
        print_usage();
    }

    if (opt_r && argc==6 && sha1 == NULL) {
        print_usage();
    }

    disk_name = argv[optind];
    int disk_input = open(disk_name, O_RDWR);
    if(disk_input == -1){
        fprintf(stderr, "Error: Failed to open disk image.");
        exit(EXIT_FAILURE);
    }
    struct stat sb;
    if(fstat(disk_input, &sb) == -1){
        fprintf(stderr, "Error: Failed to get disk file size.");
        exit(EXIT_FAILURE);
    }
    char *disk_ptr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, disk_input, 0);
    if(disk_ptr == MAP_FAILED){
        fprintf(stderr, "Error: Failed to map disk image.");
        exit(EXIT_FAILURE);
    }
    
    BootEntry *boot_entry = (BootEntry *)disk_ptr;
    int sectors_per_cluster = boot_entry->BPB_SecPerClus;
    int bytes_per_sector = boot_entry->BPB_BytsPerSec;
    int reserved_sector_count = boot_entry->BPB_RsvdSecCnt;
    int num_fats = boot_entry->BPB_NumFATs;
    int sectors_per_fat = boot_entry->BPB_FATSz32;
    int total_fat_sector_count = num_fats * sectors_per_fat;
    int bytes_per_fat = boot_entry->BPB_FATSz32 * bytes_per_sector;
    int bytes_per_cluster = sectors_per_cluster * bytes_per_sector;


    if (opt_i) {
        print_file_system_info(boot_entry);
    }

    if (opt_l) {
        int fat_start_offset = reserved_sector_count * bytes_per_sector;
        int *fat = (int *) (disk_ptr + fat_start_offset);
        
        int cluster = boot_entry->BPB_RootClus;
        int cluster_start_offset = 0;
        int count, total_count=0, max_count = bytes_per_cluster/32; // 32 is size of dir entry

        while(cluster < 0x0ffffff7){
            count = 0;
            cluster_start_offset = (reserved_sector_count + total_fat_sector_count + ((cluster-2) * sectors_per_cluster)) * bytes_per_sector;
            DirEntry *dir_entry = (DirEntry *)(disk_ptr + cluster_start_offset);
            int i = 0;
            while(dir_entry[i].DIR_Name[0] != 0x00
            && count < max_count
            && dir_entry[i].DIR_Attr != 0
            ){
                if(dir_entry[i].DIR_Name[0] == 0xe5){
                    i++;
                    continue;
                }
                if(dir_entry[i].DIR_Attr == 0x0f){
                    i++;
                    continue;
                }
                if(dir_entry[i].DIR_Name[0] == 0x2E && dir_entry[i].DIR_Attr == 16){
                    i++;
                    continue;
                }
                print_directory_entry(dir_entry[i]);
                i++;
                count++;
            }
            total_count += count;
            cluster = fat[cluster];  
        }
        printf("Total number of entries = %d\n", total_count);
    }

    if (opt_R){
        int fat_start_offset = reserved_sector_count * bytes_per_sector;
        int *fat = (int *) (disk_ptr + fat_start_offset);

        int cluster = boot_entry->BPB_RootClus;
        int cluster_start_offset = 0;

        int max_count = bytes_per_cluster/32, count, recovered = 0;

        while(cluster < 0x0ffffff7){
            count = 0;
            cluster_start_offset = (reserved_sector_count + total_fat_sector_count + ((cluster-2) * sectors_per_cluster)) * bytes_per_sector;
            DirEntry *dir_entry = (DirEntry *)(disk_ptr + cluster_start_offset);
            int i = 0;
            while(dir_entry[i].DIR_Name[0] != 0x00 
            && count < max_count
            && dir_entry[i].DIR_Attr != 0){
                if(dir_entry[i].DIR_Name[0] == 0xe5){
                    if(is_file_to_recover(dir_entry[i].DIR_Name, filename)){
                        if(is_sha1_noncont_match_and_recovered(dir_entry, i, sha1, disk_ptr, fat, fat_start_offset, num_fats, bytes_per_fat, bytes_per_cluster, filename)){
                            recovered = 1;
                            break;
                        }
                    }
                }
                i++;
                count++;
            }
            if(recovered){
                break;
            }
            cluster = fat[cluster];
        }

        if(recovered){
            printf("%s: successfully recovered with SHA-1\n", filename);
        } else {
            printf("%s: file not found\n", filename);
        }
    }

    if (opt_r){
        int fat_start_offset = reserved_sector_count * bytes_per_sector;
        int *fat = (int *) (disk_ptr + fat_start_offset);

        int cluster = boot_entry->BPB_RootClus;
        int cluster_start_offset = 0;

        int file_match_count = 0, index, max_count=bytes_per_cluster/32, count, sha1_match_found = 0;
        DirEntry *dir_entry_to_rec = NULL;
        while(cluster < 0x0ffffff7){
            count = 0;
            cluster_start_offset = (reserved_sector_count + total_fat_sector_count + ((cluster-2) * sectors_per_cluster)) * bytes_per_sector;
            DirEntry *dir_entry = (DirEntry *)(disk_ptr + cluster_start_offset);
            int i = 0;
            while(dir_entry[i].DIR_Name[0] != 0x00 
            && count < max_count
            && dir_entry[i].DIR_Attr != 0){
                if(dir_entry[i].DIR_Name[0] == 0xe5){
                    if(is_file_to_recover(dir_entry[i].DIR_Name, filename)){
                        if(sha1 != NULL){
                            if(is_sha1_match(dir_entry[i], sha1, disk_ptr, fat_start_offset, num_fats, bytes_per_fat, bytes_per_cluster)){
                                dir_entry_to_rec = dir_entry;
                                index = i;
                                file_match_count = 1;
                                sha1_match_found = 1;
                                break;
                            }
                        } else {
                            dir_entry_to_rec = dir_entry;
                            index = i;
                            file_match_count++;
                        }
                    }
                }
                i++;
                count++;
            }
            if(sha1_match_found){
                break;
            }
            cluster = fat[cluster];
        }
        
        if(file_match_count > 1){
            printf("%s: multiple candidates found\n", filename);
        } else if(file_match_count == 1){
            recover_contiguous_file(dir_entry_to_rec, index, filename, disk_ptr, fat_start_offset, num_fats, bytes_per_fat, bytes_per_cluster);
            if(sha1_match_found){
                printf("%s: successfully recovered with SHA-1\n", filename);
            } else {
                printf("%s: successfully recovered\n", filename);
            }
        } else {
            printf("%s: file not found\n", filename);
        }
    }
    

    close(disk_input);

    return 0;
}


/* References:
- Lectures notes and slides
- https://www.rapidtables.com/convert/number/decimal-to-hex.html
- https://stackoverflow.com/questions/12989969/what-does-0x0f-mean-and-what-does-this-code-mean
- https://stackoverflow.com/questions/72322810/how-to-merge-bytes-together-in-c-language
- https://stackoverflow.com/questions/1726302/remove-spaces-from-a-string-in-c
- https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
*/