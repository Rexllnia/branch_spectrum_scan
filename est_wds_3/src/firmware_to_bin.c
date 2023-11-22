#include <stdio.h>
#include <stdint.h>
#include <endian.h>
#include <unistd.h>

#define IH_MAGIC	0x27051956	/* Image Magic Number		*/
#define IH_NMLEN		32	/* Image Name Length		*/

typedef struct image_header {
	uint32_t	ih_magic;	/* Image Header Magic Number	*/
	uint32_t	ih_hcrc;	/* Image Header CRC Checksum	*/
	uint32_t	ih_time;	/* Image Creation Timestamp	*/
	uint32_t	ih_size;	/* Image Data Size		*/
	uint32_t	ih_load;	/* Data	 Load  Address		*/
	uint32_t	ih_ep;		/* Entry Point Address		*/
	uint32_t	ih_dcrc;	/* Image Data CRC Checksum	*/
	uint8_t		ih_os;		/* Operating System		*/
	uint8_t		ih_arch;	/* CPU architecture		*/
	uint8_t		ih_type;	/* Image Type			*/
	uint8_t		ih_comp;	/* Compression Type		*/
	uint8_t		ih_name[IH_NMLEN];	/* Image Name		*/
} image_header_t;

#define SQUASHFS_MAGIC		0x73717368
struct squashfs_super_block {
	uint32_t s_magic;
	uint32_t pad0[9];
	uint64_t bytes_used;
};

static int firmware_to_bin(const char *filename, unsigned erasesize)
{
	unsigned char magic[4] = {0xDE, 0xAD, 0xC0, 0xDE};
	struct squashfs_super_block sqsb;
    image_header_t ihdr;
    FILE *fd;
    long ofs;

    fd = fopen(filename, "rwb");
    if (fd == NULL) {
        printf("No such file: %s.\r\n", filename);
        return -1;	
    }

    /* get kernel size */
    if (fread((void *) &ihdr, sizeof(image_header_t), 1, fd) != 1) {
    	printf("read kernel header failed.\r\n");
    	goto err;
    }

    if (be32toh(ihdr.ih_magic) != IH_MAGIC) {
    	printf("invalid kernel header\r\n");
    	goto err;
    }
    ofs = be32toh(ihdr.ih_size) + sizeof(image_header_t);

    /* get rootfs size */
    if (fseek(fd, ofs, SEEK_SET) < 0) {
    	goto err;
    }
    if (fread((void *) &sqsb, sizeof(struct squashfs_super_block), 1, fd) != 1) {
        printf("read rootfs header failed.\r\n");
        goto err;	
    }

    if (le32toh(sqsb.s_magic) != SQUASHFS_MAGIC) {
    	printf("invalid rootfs header: 0x%x.\r\n", le32toh(sqsb.s_magic));
    	goto err;
    }

    fclose(fd);

    ofs += le64toh(sqsb.bytes_used);
    /* 现在ofs就是kernel+rootfs的大小 需要将文件大小对齐到block size */
    ofs = (ofs + erasesize - 1) & ~(erasesize - 1);

    printf("ofs=0x%x.\r\n", ofs);

    if (truncate(filename, ofs) != 0) {
        printf("truncate to %d bytes failed.\r\n", ofs);
        return -1;
    }

    /* 往文件末尾追加一个魔数 */
    fd = fopen(filename, "ab+");
    if (fd == NULL) {
        printf("No such file: %s.\r\n", filename);
        return -1;	
    }

    if (fwrite((void *) magic, sizeof(magic), 1, fd) != 1) {
        printf("append magic number to file failed.\r\n");
        goto err;
    }
    fclose(fd);
    return 0;
err:
	fclose(fd);
	return -1;
}

int main(int argc, char **argv)
{
	const char *filename;
	unsigned erasesize;

	if (argc != 3) {
	    printf("Usage: %s filename erasesize.\r\n", argv[0]);
	    return 1;	
	}

	filename  = argv[1];
	erasesize = atoi(argv[2]);

	if (firmware_to_bin(filename, erasesize) != 0) {
	    remove(filename);
	    return 1;
	}
	return 0;
}