////////////////////////////////////////////////////////////////////////
//
// Copyright 2015 PMC-Sierra, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you
// may not use this file except in compliance with the License. You may
// obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0 Unless required by
// applicable law or agreed to in writing, software distributed under the
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for
// the specific language governing permissions and limitations under the
// License.
//
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
//
//   Author: Logan Gunthorpe
//
//   Description:
//     RDMA Test Client
//
////////////////////////////////////////////////////////////////////////

#include <infiniband/verbs.h>
#include <rdma/rdma_verbs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

const size_t len = 4 * (1 << 20);
const size_t offset = 8;

static struct rdma_cm_id *do_connect(char *addr, char *port)
{
	struct rdma_cm_id *id;
	struct rdma_addrinfo hints, *res;
	struct ibv_qp_init_attr attr;

	memset(&hints, 0, sizeof hints);
	hints.ai_port_space = RDMA_PS_TCP;
	if (rdma_getaddrinfo(addr, port, &hints, &res)) {
		perror("rdma_getaddrinfo");
		return NULL;
	}

	memset(&attr, 0, sizeof attr);
	attr.cap.max_send_wr = attr.cap.max_recv_wr = 16;
	attr.cap.max_send_sge = attr.cap.max_recv_sge = 16;
	attr.cap.max_inline_data = 0;
	attr.qp_context = id;
	attr.sq_sig_all = 1;
	int ret = rdma_create_ep(&id, res, NULL, &attr);
	rdma_freeaddrinfo(res);
	if (ret) {
		perror("rdma_create_ep");
		return NULL;
	}

	if (rdma_connect(id, NULL)) {
		perror("rdma_connect");
		return NULL;
	}

	return id;
}

static void init_file(int fd)
{
	lseek(fd, 0, SEEK_SET);
	void *buf = malloc(len);
	memset(buf, 0, len);
	write(fd, buf, len);
	fsync(fd);
}

static void check_file(const char *fname, int byte_len, int mask)
{
	int fd = open(fname, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error opening %s: %m\n", fname);
		exit(1);
	}

	uint32_t *map = mmap(NULL, byte_len + offset,
			     PROT_READ, MAP_SHARED, fd, 0);
	uint32_t *d = map;

	for (int i = 0; i < offset / sizeof(*d); i++) {
		if (*d != 0) {
			printf("Offset %d not zero'd: %08" PRIx32 "\n", i, *d);
		}
		d++;
	}

	for (int i = 0; i < (byte_len - offset) / sizeof(*d); i++) {
		if (*d != (mask | i)) {
			printf("Incorrect Value at %d: %08" PRIx32 " %08x\n", i,
			       *d, mask | i);
			exit(5);
		}
		d++;
	}

	munmap(map, byte_len + offset);
	close(fd);

	printf("PASSED: File matches expected data!\n");
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		printf("USAGE: %s SERVER FILE\n", argv[0]);
		return 1;
	}

	int fd = open(argv[2], O_RDWR | O_CREAT, 0664);
	if (fd < 0) {
		fprintf(stderr, "Error opening %s: %m\n", argv[2]);
		return 1;
	}

	init_file(fd);

	void *m = mmap(NULL, len, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);

	printf("Mmap Buffer: %p\n", m);
	if (m == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	close(fd);

	struct rdma_cm_id *id = do_connect(argv[1], "11935");
	if (!id)
		return 3;

	uint32_t mask = *((uint32_t *) id->event->param.conn.private_data);
	printf("Mask: %08x\n", mask);

	struct ibv_mr *mr = ibv_reg_mr(id->pd, m+offset, len-offset,
				       IBV_ACCESS_LOCAL_WRITE |
				       IBV_ACCESS_REMOTE_WRITE |
				       IBV_ACCESS_REMOTE_READ);

	if (mr == NULL) {
		perror("ibv_reg_mr");
		return 4;
	}

	munmap(m, len);

	printf("Posting Recv\n");
	rdma_post_recv(id, NULL, m+offset, len-offset, mr);

	struct ibv_wc wc;
	rdma_get_recv_comp(id, &wc);
	printf("Recv'd: %d\n", wc.status);

	if (ibv_dereg_mr(mr))
		perror("ibv_dereg_mr");

	check_file(argv[2], wc.byte_len, mask);

	return 0;
}
