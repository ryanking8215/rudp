#ifndef _RUDP_H
#define _RUDP_H

#include <stdint.h>

typedef struct {
    void * (*malloc)(size_t size);
    // void * (*calloc)(size_t nmemb, size_t size);
    // void * (*realloc)(void *ptr, size_t size);
    void (*free)(void *ptr);
} RudpAllocator;

int rudp_init(RudpAllocator * alloc);

typedef struct {
    RUDP_STATE_CLOSED = 0,
    RUDP_STATE_LISTEN,
    RUDP_STATE_SYN_SENT,
    RUDP_STATE_SYN_RCVD,
    RUDP_STATE_SYN_OPEN,
    RUDP_STATE_CLOSE_WAIT,
} RudpState;

typedef struct {
    uint16_t max_seg_size;
    uint8_t swnd;
    uint16_t retrans_timeout, cum_ack_timeout, null_seg_timeout, trans_state_timeout;
    uint8_t max_retrans, max_cum_ack, max_out_of_seq, max_auto_reset;
} RudpSynParam;

typedef struct Rudp Rudp;

Rudp * rudp_new(uint32_t conv_id, int use_checksum);
void rudp_free(Rudp *rudp);

int rudp_listen(Rudp *rudp);
int rudp_open(Rudp *rudp);

// int rudp_set_window(Rudp *rudp, uint32_t rwnd, uint32_t swnd);
// int rudp_set_mtu(Rudp *rudp, uint32_t mtu);
// int rudp_set_timeout(Rudp *rudp, uint16_t retrans_timeout, uint16_t ack_timeout);

int rudp_recv(Rudp *rudp, uint8_t *buf, uint32_t len);
int rudp_send(Rudp *rudp, const uint8_t *buf, uint32_t len);

int rudp_input(Rudp *rudp, const uint8_t *data, uint32_t len);
int rudp_notify(Rudp *rudp, uint32_t tick);
int rudp_get_next_clock(Rudp *rudp, uint32_t tick, uint32_t *timeout);

#endif
