/*
 * Copyright 2015 Jonathan Eyolfson
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static
int elf_simple_executable(const uint8_t *input, size_t input_size,
                          uint8_t **output, size_t *output_size)
{
	const uint16_t elf_header_size = 52;
	const uint16_t program_header_size = 32;
	const uint16_t section_header_size = 40;
	const uint32_t address = 0x10000;

	size_t data_size = elf_header_size + program_header_size + input_size;
	uint8_t *data = malloc(data_size);

	if (data == NULL)
		return 1;

	data[ 0] = 0x7f;
	data[ 1] = 0x45;
	data[ 2] = 0x4c;
	data[ 3] = 0x46;
	data[ 4] = 0x01;
	data[ 5] = 0x01;
	data[ 6] = 0x01;
	data[ 7] = 0x03;
	data[ 8] = 0x00;
	data[ 9] = 0x00;
	data[10] = 0x00;
	data[11] = 0x00;
	data[12] = 0x00;
	data[13] = 0x00;
	data[14] = 0x00;
	data[15] = 0x00;
	*((uint16_t *)(data + 16)) = 0x0002;
	*((uint16_t *)(data + 18)) = 0x0028;
	*((uint32_t *)(data + 20)) = 0x00000001;
	*((uint32_t *)(data + 24)) = address + elf_header_size
	                             + program_header_size;
	*((uint32_t *)(data + 28)) = elf_header_size;
	*((uint32_t *)(data + 32)) = 0x00000000;
	*((uint32_t *)(data + 36)) = 0x05000402;
	*((uint16_t *)(data + 40)) = elf_header_size;
	*((uint16_t *)(data + 42)) = program_header_size;
	*((uint16_t *)(data + 44)) = 0x0001;
	*((uint16_t *)(data + 46)) = section_header_size;
	*((uint16_t *)(data + 48)) = 0x0000;
	*((uint16_t *)(data + 50)) = 0x0000;

	*((uint32_t *)(data + 52)) = 0x00000001;
	*((uint32_t *)(data + 56)) = 0x00000000;
	*((uint32_t *)(data + 60)) = address;
	*((uint32_t *)(data + 64)) = address;
	*((uint32_t *)(data + 68)) = data_size;
	*((uint32_t *)(data + 72)) = data_size;
	*((uint32_t *)(data + 76)) = 0x00000005;
	*((uint32_t *)(data + 80)) = 0x00000100;

	memcpy(data + (elf_header_size + program_header_size),
	       input, input_size);

	*output = data;
	*output_size = data_size;
	return 0;
}

int main(int argc, char **argv)
{
	printf("Prime 0.0.1-development\n");

	mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	int fd = open("prime-test", O_WRONLY | O_CREAT, mode);
	if (fd == -1)
		return 1;

	/* linux.exit(0) */
	uint8_t instructions[12];
	/* mov r7, #1 */
	*((uint32_t *)(instructions + 0)) = 0xe3a07001;
	/* mov r0, #0 */
	*((uint32_t *)(instructions + 4)) = 0xe3a00000;
	/* svc #0 */
	*((uint32_t *)(instructions + 8)) = 0xef000000;

	uint8_t *data;
	size_t data_size;
	if (elf_simple_executable(instructions, ARRAY_SIZE(instructions),
	                          &data, &data_size) != 0) {
		close(fd);
		return 1;
	}

	int ret = 0;
	if (write(fd, data, data_size) != (ssize_t)data_size)
		ret = 1;
	close(fd);
	free(data);
	return ret;
}
