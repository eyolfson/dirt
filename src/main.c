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

enum arm_mnemonic { MOV };
enum arm_register { R7 };

typedef uint32_t arm_arm_t;

static
void arm_condition_print(uint8_t v)
{
	if (v >= 16) {
		printf("Out of range\n");
	}
	switch (v) {
	case 0:
		printf("EQ\n");
		break;
	case 1:
		printf("NE\n");
		break;
	case 2:
		printf("CS\n");
		break;
	case 3:
		printf("CC\n");
		break;
	case 4:
		printf("MI\n");
		break;
	case 5:
		printf("PL\n");
		break;
	case 6:
		printf("VS\n");
		break;
	case 7:
		printf("VC\n");
		break;
	case 8:
		printf("HI\n");
		break;
	case 9:
		printf("LS\n");
		break;
	case 10:
		printf("GE\n");
		break;
	case 11:
		printf("LT\n");
		break;
	case 12:
		printf("GT\n");
		break;
	case 13:
		printf("LE\n");
		break;
	case 14:
		printf("AL\n");
		break;
	case 15:
		printf("AL\n");
		break;
	};
}

static
void arm_arm_print(arm_arm_t arm_arm)
{
	uint8_t condition = arm_arm & 0xf0000000;
	arm_condition_print(condition);
}

static
int arm_mnemonic_parse(char *input, size_t remaining,
                       enum arm_mnemonic *mnemonic, size_t *handled)
{
	if (remaining >= 3) {
		if (strncmp(input, "mov", 3) == 0) {
			*mnemonic = MOV;
			*handled = 3;
			return 0;
		}
	}
	return 1;
}

static
int arm_register_parse(char *input, size_t remaining,
                       enum arm_register *arm_register, size_t *handled)
{
	if (remaining >= 2) {
		if (strncmp(input, "r7", 2) == 0) {
			*arm_register = R7;
			*handled = 2;
			return 0;
		}
	}
	return 1;
}

static
int arm_instructions(char *input, size_t input_size,
                     uint8_t **output, size_t output_size)
{
	char *current = input;
	const char *const input_end = input + input_size;
	uint8_t state = 0;
	enum arm_mnemonic arm_mnemonic;
	enum arm_register arm_register;
	size_t handled;
	while (current != input_end) {
		if (*current == ' ') {
			++current;
			continue;
		}
		size_t remaining = input_end - current;
		switch (state) {
		case 0:
			if (arm_mnemonic_parse(current, remaining,
			                       &arm_mnemonic, &handled) != 0) {
				return 1;
			}
			current += handled;
			state = 1;
			continue;
		case 1:
			if (arm_register_parse(current, remaining,
			                       &arm_register, &handled) != 0) {
				return 1;
			}
			current += handled;
			state = 2;
			continue;
		case 2:
			++current;
			break;
		}
	}

	return 0;
}

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

	char text[] = "mov r7 1";
	if (arm_instructions(text, ARRAY_SIZE(text) - 1, 0, 0) != 0) {
		printf("Fail\n");
		return 1;
	}

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
