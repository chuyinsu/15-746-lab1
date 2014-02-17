/* $cmuPDL: readwrite.c,v 1.3 2010/02/27 11:38:39 rajas Exp $ */
/* $cmuPDL: readwrite.c,v 1.4 2014/01/26 21:16:20 avjaltad Exp $ */
/* readwrite.c
 *
 * Code to read and write sectors to a "disk" file.
 * This is a support file for the "fsck" storage systems laboratory.
 *
 * author: Yinsu Chu (yinsuc)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     /* for memcpy() */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include "genhd.h"
#include "ext2_fs.h"

#if defined(__FreeBSD__)
# define lseek64 lseek
#endif

//#define DEBUG
#ifdef DEBUG
# define dbg_print(...) printf(__VA_ARGS__)
#else
# define dbg_print(...) 
#endif

/* MBR starts at sector 0 with length of 1 sector */
#define MBR_SECT_INDEX (0)
#define MBR_SECT_LEN (1)

/* partition number starts at 1 */
#define FIRST_PARTITION_NUM (1)

#define BS_CODE_SIZE (446)
#define PRI_PAR_NUM (4)
#define SB_OFFSET (1024)
#define SB_SIZE (sizeof(Superblock))
#define GD_SIZE (sizeof(Groupdesc))
#define INODE_SIZE (sizeof(Inode))
#define SECTOR_SIZE_BYTES (512)
#define SB_SECTOR_OFFSET (SB_OFFSET / SECTOR_SIZE_BYTES)
#define SB_SECTOR_LEN (SB_SIZE / SECTOR_SIZE_BYTES)
#define BLOCK_SIZE_UNIT (1024)

/* linux: lseek64 declaration needed here to eliminate compiler warning. */
extern int64_t lseek64(int, int64_t, int);

static int device;  /* disk file descriptor */

static const char *optstring = "p:i:f:";

static int block_size = 1;
static int sect_per_block = 1;
typedef struct partition Partition;
typedef struct ext2_super_block Superblock;
typedef struct ext2_group_desc Groupdesc;
typedef struct ext2_inode Inode;
typedef struct ext2_dir_entry_2 Directory;

int get_target_partition(unsigned char *mbr, int target_id, unsigned int *sect);
int get_target_partition_ext(unsigned int base_sect, unsigned int ext_sect, int *par_id, int target_id, unsigned int *sect);

/* print_sector: print the contents of a buffer containing one sector.
 *
 * inputs:
 *   char *buf: buffer must be >= 512 bytes.
 *
 * outputs:
 *   the first 512 bytes of char *buf are printed to stdout.
 *
 * modifies:
 *   (none)
 */
void print_sector (unsigned char *buf)
{
    int i;
    for (i = 0; i < SECTOR_SIZE_BYTES; i++) {
        printf("%02x", buf[i]);
        if (!((i+1) % 32))
            printf("\n");      /* line break after 32 bytes */
        else if (!((i+1) % 4))
            printf(" ");   /* space after 4 bytes */
    }
}


/* read_sectors: read a specified number of sectors into a buffer.
 *
 * inputs:
 *   int64 start_sector: the starting sector number to read.
 *                       sector numbering starts with 0.
 *   int numsectors: the number of sectors to read.  must be >= 1.
 *   int device [GLOBAL]: the disk from which to read.
 *
 * outputs:
 *   void *into: the requested number of sectors are copied into here.
 *
 * modifies:
 *   void *into
 */
void read_sectors (int64_t start_sector, unsigned int num_sectors, void *into)
{
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_read;

    if (num_sectors == 1) {
        dbg_print("Reading sector %"PRId64"\n", start_sector);
    } else {
        dbg_print("Reading sectors %"PRId64"--%"PRId64"\n",
                start_sector, start_sector + (num_sectors - 1));
    }

    sector_offset = start_sector * SECTOR_SIZE_BYTES;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(-1);
    }

    bytes_to_read = SECTOR_SIZE_BYTES * num_sectors;

    if ((ret = read(device, into, bytes_to_read)) != bytes_to_read) {
        fprintf(stderr, "Read sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(-1);
    }
}


/* write_sectors: write a buffer into a specified number of sectors.
 *
 * inputs:
 *   int64 start_sector: the starting sector number to write.
 *                	sector numbering starts with 0.
 *   int numsectors: the number of sectors to write.  must be >= 1.
 *   void *from: the requested number of sectors are copied from here.
 *
 * outputs:
 *   int device [GLOBAL]: the disk into which to write.
 *
 * modifies:
 *   int device [GLOBAL]
 */
void write_sectors (int64_t start_sector, unsigned int num_sectors, void *from)
{
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_write;

    if (num_sectors == 1) {
        dbg_print("Reading sector  %"PRId64"\n", start_sector);
    } else {
        dbg_print("Reading sectors %"PRId64"--%"PRId64"\n",
                start_sector, start_sector + (num_sectors - 1));
    }

    sector_offset = start_sector * SECTOR_SIZE_BYTES;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(-1);
    }

    bytes_to_write = SECTOR_SIZE_BYTES * num_sectors;

    if ((ret = write(device, from, bytes_to_write)) != bytes_to_write) {
        fprintf(stderr, "Write sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(-1);
    }
}

int main (int argc, char **argv)
{
    int op = 0;
    int par_num = -1;
    int display_partition = 0;
    int par_fix = -1;
    int fix_partition = 0;
    char *disk_path = NULL;

    while ((op = getopt(argc, argv, optstring)) != -1) {
        switch (op) {
            case 'p':
                par_num = (int) strtol(optarg, NULL, 10);
                display_partition = 1;
                break;
            case 'i':
                disk_path = strdup(optarg);
                break;
            case 'f':
                par_fix = (int) strtol(optarg, NULL, 10);
                fix_partition = 1;
                break;
        }
    }

    dbg_print("partition to display: %d\n", par_num);
    dbg_print("disk path: %s\n", disk_path);
    dbg_print("partition to fix: %d\n", par_fix);

    if ((device = open(disk_path, O_RDWR)) == -1) {
        perror("Could not open device file");
        exit(-1);
    }

    dbg_print("device opened");

    unsigned char mbr[SECTOR_SIZE_BYTES] = "";
    read_sectors(MBR_SECT_INDEX, MBR_SECT_LEN, mbr);

    dbg_print("MBR read\n");

    free(disk_path);

    if (display_partition) {
        if (!get_target_partition(mbr, par_num, NULL)) {
            printf("%d\n", -1);
        }
    }

    unsigned int par_start_sect = 0;
    int found_par = 0;
    if (fix_partition) {
        par_num = FIRST_PARTITION_NUM;
        found_par = get_target_partition(mbr, par_num, &par_start_sect);
        while (found_par) {
            if ((par_fix == 0 || par_fix == par_num) && (par_start_sect != 0)) {
                dbg_print("fixing partition %d starting at sector %d\n", par_num, par_start_sect);
                // fix this partition
            }
            par_num++;
            found_par = get_target_partition(mbr, par_num, &par_start_sect);
        }
    }

    close(device);
    return 0;
}

int get_target_partition(unsigned char *mbr, int target_id, unsigned int *sect)
{
    if (target_id <= 0) {
        return 0;
    }

    Partition *pp = NULL;
    if (target_id <= PRI_PAR_NUM) {
        pp = (Partition *) (mbr + BS_CODE_SIZE + (target_id - 1) * sizeof(Partition));
        if (sect != NULL) {
            if (pp->sys_ind != DOS_EXTENDED_PARTITION && pp->sys_ind != LINUX_EXTENDED_PARTITION && pp->sys_ind != WIN98_EXTENDED_PARTITION) {
                *sect = pp->start_sect;
            } else {
                *sect = 0;
            }
        } else {
            printf("0x%02X %d %d\n", pp->sys_ind, pp->start_sect, pp->nr_sects);
        }
        return 1;
    }

    int i = 0;
    int par_id = 4;
    for (i = 0; i < PRI_PAR_NUM; i++) {
        pp = (Partition *) (mbr + BS_CODE_SIZE + i * sizeof(Partition));
        if (pp->sys_ind == DOS_EXTENDED_PARTITION || pp->sys_ind == LINUX_EXTENDED_PARTITION || pp->sys_ind == WIN98_EXTENDED_PARTITION) {
            if (get_target_partition_ext(pp->start_sect, pp->start_sect, &par_id, target_id, sect)) {
                return 1;
            }
        }
    }
    return 0;
}

int get_target_partition_ext(unsigned int base_sect, unsigned int ext_sect, int *par_id, int target_id, unsigned int *sect)
{
    Partition *pp = NULL;
    unsigned char ext[SECTOR_SIZE_BYTES];

    read_sectors(ext_sect, 1, ext);
    pp = (Partition *) (ext + BS_CODE_SIZE);

    (*par_id)++;
    if (*par_id == target_id) {
        if (sect != NULL) {
            *sect = ext_sect + pp->start_sect;
        } else {
            printf("0x%02X %d %d\n", pp->sys_ind, ext_sect + pp->start_sect, pp->nr_sects);
        }
        return 1;
    }

    pp = (Partition *) (ext + BS_CODE_SIZE + sizeof(Partition));
    if (pp->sys_ind == DOS_EXTENDED_PARTITION || pp->sys_ind == LINUX_EXTENDED_PARTITION || pp->sys_ind == WIN98_EXTENDED_PARTITION) {
        if (get_target_partition_ext(base_sect, base_sect + pp->start_sect, par_id, target_id, sect)) {
            return 1;
        }
    }
    return 0;
}





void read_bytes(int64_t start_byte, unsigned int num_bytes, void *into)
{
    ssize_t ret;
    int64_t lret;

    if ((lret = lseek64(device, start_byte, SEEK_SET)) != start_byte) {
        fprintf(stderr, "Seek to byte %"PRId64" failed: "
                "returned %"PRId64"\n", start_byte, lret);
        exit(-1);
    }

    if ((ret = read(device, into, num_bytes)) != num_bytes) {
        fprintf(stderr, "Read byte %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_byte, num_bytes, ret);
        exit(-1);
    }
}

void get_super_block(unsigned int par_start_sect, Superblock *sb)
{
    read_sectors(par_start_sect + SB_SECTOR_OFFSET, SB_SECTOR_LEN, (void *) sb);
}

void get_group_desc(unsigned int par_start_sect, int group_id, Groupdesc *gd)
{
    unsigned int gd_start_sect = par_start_sect + SB_SECTOR_OFFSET + SB_SECTOR_LEN;
    unsigned int gd_start_byte = gd_start_sect * SECTOR_SIZE_BYTES + group_id * GD_SIZE;
    read_bytes(gd_start_byte, GD_SIZE, (void *) gd);
}



void get_inode(unsigned int par_start_sect, int inode_id, Inode *inode)
{
    dbg_print("partition starts at %d\n", par_start_sect);
    unsigned char super_block_buf[SB_SIZE] = "";
    unsigned char group_desc_buf[GD_SIZE] = "";
    get_super_block(par_start_sect, (Superblock *) super_block_buf);
    Superblock *sbp = (Superblock *) super_block_buf;
    dbg_print("superblock magic: %d\n", sbp->s_magic);
    unsigned int group_id = (inode_id - 1) / sbp->s_inodes_per_group;
    get_group_desc(par_start_sect, group_id, (Groupdesc *) group_desc_buf);
    Groupdesc *gdp = (Groupdesc *) group_desc_buf;
    dbg_print("group desc inode table: %d\n", gdp->bg_inode_table);
    unsigned int inode_index = (inode_id - 1) % sbp->s_inodes_per_group;
    unsigned int inode_start_byte = par_start_sect * SECTOR_SIZE_BYTES + gdp->bg_inode_table * block_size + inode_index * INODE_SIZE;
    dbg_print("sector bytes: %d\n", par_start_sect * SECTOR_SIZE_BYTES);
    dbg_print("block bytes: %d\n", gdp->bg_inode_table * block_size);
    dbg_print("inode offset: %d\n", inode_index * INODE_SIZE);
    dbg_print("inode starts at byte %d\n", inode_start_byte);
    read_bytes(inode_start_byte, INODE_SIZE, (void *) inode);
}

void get_block_bitmap(unsigned int par_start_sect, unsigned int group_id, unsigned char *bitmap)
{
    unsigned char group_desc_buf[GD_SIZE] = "";
    get_group_desc(par_start_sect, group_id, (Groupdesc *) group_desc_buf);
    Groupdesc *gdp = (Groupdesc *) group_desc_buf;
    read_sectors(par_start_sect + gdp->bg_block_bitmap * sect_per_block, sect_per_block, bitmap);
}

void get_inode_bitmap(unsigned int par_start_sect, unsigned int group_id, unsigned char *bitmap)
{
    unsigned char group_desc_buf[GD_SIZE] = "";
    get_group_desc(par_start_sect, group_id, (Groupdesc *) group_desc_buf);
    Groupdesc *gdp = (Groupdesc *) group_desc_buf;
    read_sectors(par_start_sect + gdp->bg_inode_bitmap * sect_per_block, sect_per_block, bitmap);
}

/* EOF */
