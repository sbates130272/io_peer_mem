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
//     RDMA Test Server
//
////////////////////////////////////////////////////////////////////////

#include <rdma/rdma_verbs.h>

#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

struct rdma_cm_id *setup_server(void)
{
    struct rdma_addrinfo hints, *res;
    struct ibv_qp_init_attr attr;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags = RAI_PASSIVE;
    hints.ai_port_space = RDMA_PS_TCP;
    if (rdma_getaddrinfo(NULL, "11935", &hints, &res)) {
        perror("rdma_getaddrinfo");
        return NULL;
    }

    struct rdma_cm_id *listen_id;

    memset(&attr, 0, sizeof attr);
    attr.cap.max_send_wr = attr.cap.max_recv_wr = 8;
    attr.cap.max_send_sge = attr.cap.max_recv_sge = 8;
    attr.cap.max_inline_data = 16;
    attr.sq_sig_all = 1;
    if (rdma_create_ep(&listen_id, res, NULL, &attr)) {
        perror("rdma_create_ep");
        return NULL;
    }

    if (rdma_listen(listen_id, 0)) {
        perror("rdma_listen");
        return NULL;
    }

    return listen_id;
}

int main(int argc, char *argv[])
{
    struct rdma_cm_id *listen_id = setup_server();
    if (listen_id == NULL)
        return 2;

    printf("Listening on port %s\n", "11935");

    srand(time(NULL));

    while(1) {
        printf("\n");
        struct rdma_cm_id *id;

        if (rdma_get_request(listen_id, &id)) {
            perror("rdma_get_request");
            return 1;
        }

        const int buflen = (1 << 19);
        uint32_t *buf = malloc(buflen * sizeof(*buf));

        uint32_t mask = rand() << 16;
        printf("Mask: %08x\n", mask);

        for (int i = 0; i < buflen; i++)
            buf[i] = mask | i;


        struct ibv_mr *mr = ibv_reg_mr(id->pd, buf, buflen*sizeof(*buf),
                                       IBV_ACCESS_LOCAL_WRITE |
                                       IBV_ACCESS_REMOTE_WRITE |
                                       IBV_ACCESS_REMOTE_READ);


        struct rdma_conn_param conn_param;
        memset(&conn_param, 0, sizeof(conn_param));
        conn_param.private_data_len = sizeof(mask);
        conn_param.private_data = &mask;
        conn_param.responder_resources = 2;
        conn_param.initiator_depth = 2;
        conn_param.retry_count = 5;
        conn_param.rnr_retry_count = 5;

        printf("Accepting Client Connection\n");
        if (rdma_accept(id, &conn_param)) {
            perror("rdma_accept");
            goto disconnect;
        }

        printf("Post Send\n");
        rdma_post_send(id, NULL, buf, buflen*sizeof(*buf),
                       mr, 0);

        struct ibv_wc wc;
        rdma_get_send_comp(id, &wc);


        printf("Sent: %d\n", wc.status);

disconnect:
        rdma_disconnect(id);
    }


    return 0;
}
