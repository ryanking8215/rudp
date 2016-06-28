#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include "rudp.h"

// http://tools.ietf.org/html/draft-ietf-sigtran-reliable-udp-00
// RFC 908

#define MIN_RUDP_HEAD_SIZE 10 // 我们自己在最上面加了conv_id, 用于区分是否是对应的rudp的包

#define DEFAULT_RETRANS_TIMEOUT 600  // in ms
#define DEFAULT_CUM_ACK_TIMEOUT 300 // in ms 
#define DEFAULT_NULL_SEG_TIMEOUT 2*1000 // in ms
#define DEFAULT_TRANSFER_STATE_TIMEOUT 1*1000 // in ms

#define DEFAULT_CUM_ACK_COUNT 3
#define DEFAULT_MAX_OUT_OF_SEQ 3

#define DEFAULT_SND_WINDOW 32
#define DEFAULT_RCV_WINDOW 32

typedef enum {
    CTRL_SYN = 1<<0,
    CTRL_ACK = 1<<1,
    CTRL_EAK = 1<<2,
    CTRL_RST = 1<<3,
    CTRL_NUL = 1<<4,
    CTRL_CHK = 1<<5,
    CTRL_TSC = 1<<6,
} ControlBit;

//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

static inline uint8_t * write8(uint8_t *p, uint8_t v)
{
    *(uint8_t *)p = v;
    return p+sizeof(v);
}

static inline uint8_t * write16(uint8_t *p, uint16_t v)
{
    *(uint16_t *)p = htons(v);
    return p+sizeof(v);
}

static inline uint8_t * write32(uint8_t *p, uint32_t v)
{
    *(uint32_t *)p = htonl(v);
    return p+sizeof(v);
}

static inline const uint8_t * read8(const uint8_t *p, uint8_t *v)
{
    *v = *p;
    return p+sizeof(*v);
}

static inline const uint8_t * read16(const uint8_t *p, uint16_t *v)
{
    *v = ntohs(*(uint16_t *)p);
    return p+sizeof(*v);
}

static inline const uint8_t * read32(const uint8_t *p, uint32_t *v)
{
    *v = ntohl(*(uint32_t *)p);
    return p+sizeof(*v);
}

static RudpAllocator DefaultAllocator = {
    .malloc = malloc,
    .free = free,
};

static RudpAllocator *g_alloc = &DefaultAllocator;

int rudp_init(RudpAllocator *alloc)
{
    if (alloc!=NULL) {
        g_alloc = alloc;
    }
    return 0;
}

struct segment {
	SIMPLEQ_ENTRY(segment) link;
    uint8_t seq;
    int miss_cnt;
    int is_ack;
    size_t size;
    uint8_t data[1];
};
typedef struct segment Segment;

SIMPLEQ_HEAD(segment_queue, segment);


Segment *segment_new(size_t len)
{
    Segment *s = g_alloc->malloc(sizeof(*s));
    if (s!=NULL) {
        s->len = len;
    }
    return s;
}

void segment_free(Segment *s)
{
    if (s!=NULL) {
        g_alloc->free(s);
    }
}

struct Rudp {
    uint32_t conv_id;
    int use_checksum;
    uint32_t mtu;
    RudpState state;
    RudpSynParam param;
    uint32_t snd_nxt, snd_una, snd_max, snd_iss, snd_wnd;
    uint32_t rcv_cur, rcv_max, rcv_irs, rcv_wnd;

    struct segment_queue snd_buf;
    struct segment_queue snd_segs;
    struct segment_queue rcv_buf;
    struct segment_queue rcv_segs;
};


Rudp * rudp_new(uint32_t conv_id, int use_checksum)
{
    Rudp *r = (Rudp *)g_alloc.malloc(sizeof(*r));
    if (r==NULL) {
        return NULL;
    }
    memset(r, 0, sizeof(*r));
    r->conv_id = conv_id;
    r->use_checksum = use_checksum;
    r->state = RUDP_STATE_CLOSED;

    SIMPLEQ_INIT(&r->snd_buf);
    SIMPLEQ_INIT(&r->snd_segs);
    SIMPLEQ_INIT(&r->rcv_buf);
    SIMPLEQ_INIT(&r->rcv_segs);

    RudpSynParam *p = &r->param;
    p->max_seg_size = 1200;
    p->swnd = 32;
    p->retrans_timeout = DEFAULT_RETRANS_TIMEOUT;
    p->cum_ack_timeout = DEFAULT_CUM_ACK_TIMEOUT;
    p->null_seg_timout = DEFAULT_NULL_SEG_TIMEOUT;
    p->max_cum_ack = DEFAULT_MAX_CUM_ACK;

    r->snd_iss = 100;
    r->snd_wnd = DEFAULT_SND_WINDOW;
    r->snd_nxt = r->snd_iss+1; 
    r->snd_una = r->snd_iss;
    r->snd_max = r->snd_una + r->snd_wnd;

    r->rcv_wnd = DEFAULT_RCV_WINDOW;

    return r;
}

int rudp_listen(Rudp *rudp)
{
    rudp->state = RUDP_STATE_LISTEN;
    return 0;
}

int rudp_open(Rudp *rudp)
{
    // SYN
    Segment *seg = segment_new(32);
    if (seg==NULL) {
        return -1;
    }
    memset(seg, 0, sizeof(*seg));
    seg->seq = rudp->snd_iss;

    uint16_t checksum = 0;
    uint8_t * ptr = seg->data;
    ptr = write32(ptr, rudp->conv_id);
    ptr = write8(ptr, (uint8_t)CTRL_SYN);
    ptr = write8(ptr, 32);
    ptr = write8(ptr, seg->seq);
    ptr = write8(ptr, 0);
    ptr = write8(ptr, 1); // ver
    ptr = write8(ptr, 1); // max number of out standing segs
    ptr = write8(ptr, 0); // opt flags
    ptr = write8(ptr, 0); // spare
    ptr = write16(ptr, rudp->param.max_seg_size); 
    ptr = write16(ptr, rudp->param.retrans_timeout); 
    ptr = write16(ptr, rudp->param.cum_ack_timeout); 
    ptr = write16(ptr, rudp->param.null_seg_timout); 
    ptr = write16(ptr, rudp->param.trans_state_timeout); 
    ptr = write8(ptr, rudp->param.max_retrans); 
    ptr = write8(ptr, rudp->param.max_cum_ack); 
    ptr = write8(ptr, rudp->param.max_out_of_seq); 
    ptr = write8(ptr, rudp->param.max_auto_reset); 
    ptr = write32(ptr, rudp->conv_id);  // connection id
    ptr = write16(ptr, checksum);

    SIMPLEQ_INSERT_TAIL(&rudp->snd_segs, seg, link);
    rudp->state = RUDP_STATE_SYN_SENT;
    return 0;
}

static void parse_una(Rudp *rudp, uint8_t ack, uint8_t *out_of_seqs, size_t out_of_cnt)
{
    // TODO ack是连续的最后一个确认序号，out_of_seqs是带乱序确认
}

int rudp_input(Rudp *rudp, uint8_t *data, uint32_t len)
{
    if (data==NULL || len < MIN_RUDP_HEAD_SIZE) {
        return -1;
    }
    const uint8_t *ptr = (const uint8_t *)data;
    uint32_t conv_id;
    uint8_t ctrl_bit, head_len, seq, ack;

    // read rudp head
    ptr = read32(ptr, &conv_id);
    if (conv_id != rudp->conv_id) {
        return -2;
    }
    ptr = read8(ptr, &ctrl_bit);
    ptr = read8(ptr, &head_len);
    ptr = read8(ptr, &seq);
    ptr = read8(ptr, &ack);

    if (ctrl_bit & CTRL_SYN) {
        RudpSynParam syn_param;
        read_syn(ptr, &syn_param);

        rudp->rcv_irs = seq; 
        rudp->rcv_cur = seq;
        rudp->rcv_max = rudp->rcv_cur + rudp->rcv_wnd;

        if (rudp->state == RUDP_STATE_LISTEN) {
            rudp->state = RUDP_STATE_SYN_RCVD;
            // TODO 构建syn-ack包
        }
    }
    if (ctrl_bit & CTRL_ACK) {
        uint8_t out_of_seqs[256]; // FIXME
        size_t out_of_cnt = 0;
        if (ctrl_bit & CTRL_EAK) {
            out_of_cnt = head_len - MIN_RUDP_HEAD_SIZE;
            read_eak(ptr, seqs);
        }
        // TODO 解析未确认的包
        parse_una(rudp, ack, out_of_seqs, out_of_cnt);
    }

#if 0
    if (len>head_len) {
        Segment *seq = segment_new(len-head_len);
        if (seq!=NULL) {
            seq->seq = seq;
            memcpy(seq->data, data+head_len, len-head_len);
        }
        // TODO 加入rcv_seq
    }
#endif
}

int rudp_recv(Rudp *rudp, uint8_t *buf, uint32_t len)
{
}

int rudp_send(Rudp *rudp, uint8_t *buf, uint32_t len)
{
    if (rudp==NULL || (len>0 && buf==NULL)) {
        return -1;
    }
    Segment *seg = segment_new(sizeof(*seg) + len);
    if (seg==NULL) {
        return -2;
    }
    if (len>0) {
        memcpy(seg->data, buf, len);
    }
    SIMPLEQ_INSERT_TAIL(&rudp->snd_buf, seg);
    return 0;
}

int rudp_notify(Rudp *rudp, uint32_t tick)
{

}

int rudp_get_next_clock(Rudp *rudp, uint32_t tick, uint32_t *timeout)
{

}
