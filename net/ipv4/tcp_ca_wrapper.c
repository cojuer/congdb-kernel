#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>

#include <net/tcp.h>
#include <net/congdb/congdb_manager.h>

#include <linux/kprobes.h>

static DEFINE_SPINLOCK(wrappers_list_lock);
static LIST_HEAD(wrappers_list);

struct sock_ca_stats
{
    uint32_t acks_num;
    uint32_t loss_num;
    uint32_t rtt;
};

struct sock_ca_data
{
    struct tcp_congestion_ops* ops;
    struct sock_ca_stats stats;
};

struct wrapper_holder
{
    struct list_head list;
    struct tcp_cong_wr_ops* ops;
};

struct tcp_cong_wr_ops
{
    struct tcp_congestion_ops ops;
    struct tcp_congestion_ops* inner;
};

// create copy of standard reno algorithm
extern void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked);
extern u32 tcp_reno_ssthresh(struct sock *sk);
extern u32 tcp_reno_undo_cwnd(struct sock *sk);

static struct tcp_congestion_ops __read_mostly reno = {
    .ssthresh	= tcp_reno_ssthresh,
    .cong_avoid	= tcp_reno_cong_avoid,
    .undo_cwnd	= tcp_reno_undo_cwnd,

    .flags		= TCP_CONG_NON_RESTRICTED,
    .owner		= THIS_MODULE,
    .name		= "reno",
};

// create wrapper for reno
static void tcp_ca_wrapper_release(struct sock *sk);
u32 tcp_ca_wrapper_ssthresh(struct sock *sk);
void tcp_ca_wrapper_cong_avoid(struct sock *sk, u32 ack, u32 acked);
u32 tcp_ca_wrapper_undo_cwnd(struct sock *sk);
void tcp_ca_wrapper_in_ack_event(struct sock *sk, u32 flags);

static struct tcp_cong_wr_ops wr_reno __read_mostly = {
    .ops = {
        .release           = tcp_ca_wrapper_release,
        .ssthresh	   = tcp_ca_wrapper_ssthresh,
        .cong_avoid	   = tcp_ca_wrapper_cong_avoid,
        .undo_cwnd	   = tcp_ca_wrapper_undo_cwnd,
        .in_ack_event      = tcp_ca_wrapper_in_ack_event,

        .flags             = TCP_CONG_NON_RESTRICTED,
        .owner		   = THIS_MODULE,
        .name		   = "wr_reno",
    },
    .inner = &reno,
};

#define PRIV_CA_SIZE ICSK_CA_PRIV_SIZE / sizeof(u64)
#define PRIV_CA_ID PRIV_CA_SIZE - 1

struct sock_ca_data* get_priv_ca_data(struct sock *sk)
{
    return ((struct sock_ca_data**)inet_csk_ca(sk))[PRIV_CA_ID];
}

struct sock_ca_stats* get_priv_ca_stats(struct sock *sk)
{
    struct sock_ca_data *data = get_priv_ca_data(sk);
    if (!data) 
    {
        pr_err("CAWR: data is NULL");
        return NULL;
    }
    return &data->stats;
}

struct tcp_congestion_ops* get_inner_ops(struct sock *sk)
{
    return ((struct tcp_cong_wr_ops*)(inet_csk(sk)->icsk_ca_ops))->inner;
}

static void tcp_ca_wrapper_init(struct sock *sk)
{
    pr_info("CAWR: init tcp_ca_wrapper");
    const char *inner_ca_name = congdb_get_entry(sk->sk_rcv_saddr, sk->sk_daddr);

    // allocate memory for socket data
    ((struct sock_ca_data**)inet_csk_ca(sk))[PRIV_CA_ID] = kmalloc(sizeof(struct sock_ca_data), GFP_KERNEL);

    // set all statistics to zeroes
    struct sock_ca_stats *stats = get_priv_ca_stats(sk);
    memset(stats, 0, sizeof(*stats));

    // look for wrapper

    // TODO: use static memory
    // allocate name to find wrapper 
    // example: reno -> wr_reno
    char *wrapper_name = kmalloc(4 + strlen(inner_ca_name), GFP_KERNEL);
    strcpy(wrapper_name, "wr_");
    strcat(wrapper_name, inner_ca_name);

    struct tcp_cong_wr_ops* wrapper = NULL;
    struct wrapper_holder *a;
    list_for_each_entry_rcu(a, &wrappers_list, list) {
        if (strcmp(a->ops->ops.name, wrapper_name) == 0) {
            wrapper = a->ops;
        }
    }
    kfree(wrapper_name);

    // set reno if wrapper or inner ca not found
    if (wrapper != NULL) {
        cadb_set_socket(sk);
        pr_info("CAWR: wrapper found: \"%s\"", wrapper->ops.name);
        inet_csk(sk)->icsk_ca_ops = (struct tcp_congestion_ops*)wrapper;
    }
    else {
        pr_err("CAWR: wrapper not found: reno will be used");
        inet_csk(sk)->icsk_ca_ops = (struct tcp_congestion_ops*)(&wr_reno);
    }

    struct tcp_congestion_ops *ops = get_inner_ops(sk);
    pr_info("CAWR: inner name \"%s\"", ops->name);
    if (ops->init)
        ops->init(sk);
}

extern void congdb_aggregate_stats(uint32_t loc_ip, uint32_t rem_ip, void *stats);
static void tcp_ca_wrapper_release(struct sock *sk)
{
    cadb_set_socket(NULL);
    struct sock_ca_data *sock_data = get_priv_ca_data(sk);
    if (sock_data == NULL)
    {
        pr_err("CAWR: sock data has been released");
        return;
    }

    // write smoothed rtt into stats
    u32 rtt = tcp_sk(sk)->srtt_us >> 3;
    get_priv_ca_stats(sk)->rtt = rtt;

    u32 retr_num = tcp_sk(sk)->total_retrans;
    get_priv_ca_stats(sk)->loss_num = retr_num;

    pr_info("rtt: %u", rtt);
    pr_info("ack: %u", get_priv_ca_stats(sk)->acks_num);
    pr_info("retr: %u", retr_num);
    pr_info("retr_out: %u", tcp_sk(sk)->retrans_out);
    pr_info("icsk_retr: %u", (u32)inet_csk(sk)->icsk_retransmits);
    pr_info("segs_out: %u", tcp_sk(sk)->segs_out);
    pr_info("data_segs_out: %u", tcp_sk(sk)->data_segs_out);

    // aggregate statistics
    congdb_aggregate_stats(sk->sk_rcv_saddr, sk->sk_daddr, get_priv_ca_stats(sk));

    pr_info("CAWR: release private sock data");

    // release inner congestion algorithm
    struct tcp_congestion_ops *ops = get_inner_ops(sk);
    if (ops->release)
        ops->release(sk);

    // free allocated sock data
    kfree(sock_data);
    
    pr_info("CAWR: session ended");
}

u32 tcp_ca_wrapper_ssthresh(struct sock *sk)
{
    struct sock_ca_stats* stats = get_priv_ca_stats(sk);
    if (stats) 
        stats->loss_num += 1;

    return get_inner_ops(sk)->ssthresh(sk);
}

void tcp_ca_wrapper_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    get_inner_ops(sk)->cong_avoid(sk, ack, acked);
}

void tcp_ca_wrapper_set_state(struct sock *sk, u8 new_state)
{
    get_inner_ops(sk)->set_state(sk, new_state);
}

void tcp_ca_wrapper_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
    get_inner_ops(sk)->cwnd_event(sk, ev);
}

void tcp_ca_wrapper_in_ack_event(struct sock *sk, u32 flags)
{
    struct sock_ca_stats* stats = get_priv_ca_stats(sk);
    if (stats) 
        stats->acks_num += 1;

    struct tcp_congestion_ops *ops = get_inner_ops(sk);
    if (ops && ops->in_ack_event)
        ops->in_ack_event(sk, flags);
}

u32 tcp_ca_wrapper_undo_cwnd(struct sock *sk)
{
    get_inner_ops(sk)->undo_cwnd(sk);
}

void tcp_ca_wrapper_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
    get_inner_ops(sk)->pkts_acked(sk, sample);
}

u32 tcp_ca_wrapper_tso_segs_goal(struct sock *sk)
{
    return get_inner_ops(sk)->tso_segs_goal(sk);
}

u32 tcp_ca_wrapper_sndbuf_expand(struct sock *sk)
{
    return get_inner_ops(sk)->sndbuf_expand(sk);
}

void tcp_ca_wrapper_cong_control(struct sock *sk, const struct rate_sample *rs)
{
    get_inner_ops(sk)->cong_control(sk, rs);
}

size_t tcp_ca_wrapper_get_info(struct sock *sk, u32 ext, int *attr,
           union tcp_cc_info *info)
{
    return get_inner_ops(sk)->get_info(sk, ext, attr, info);
}

static struct tcp_cong_wr_ops tcp_ca_wrapper __read_mostly = {
    .ops = {
        .init		   = tcp_ca_wrapper_init,
        .release           = tcp_ca_wrapper_release,
        .ssthresh	   = tcp_ca_wrapper_ssthresh,
        .cong_avoid	   = tcp_ca_wrapper_cong_avoid,
        .undo_cwnd	   = tcp_ca_wrapper_undo_cwnd,

        .owner		   = THIS_MODULE,
        .name		   = "tcp_ca_wrapper",
    },
    .inner = &reno,
};

int jtcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
    if (!ca->ssthresh || !ca->undo_cwnd ||
	!(ca->cong_avoid || ca->cong_control)) {
        jprobe_return();
        return -EINVAL;
    }

    if (strcmp(ca->name, "tcp_ca_wrapper") != 0) {
        spin_lock(&wrappers_list_lock);

        // allocate wrapper
        struct tcp_cong_wr_ops* wrapper = kmalloc(sizeof(*wrapper), GFP_KERNEL);
        memset(wrapper, 0, sizeof(*wrapper));

        // Set required members
        wrapper->ops.release = tcp_ca_wrapper_release;  
        wrapper->ops.cong_avoid = tcp_ca_wrapper_cong_avoid;
        wrapper->ops.ssthresh = tcp_ca_wrapper_ssthresh;
        wrapper->ops.in_ack_event = tcp_ca_wrapper_in_ack_event;
        wrapper->ops.undo_cwnd = tcp_ca_wrapper_undo_cwnd;
        wrapper->ops.owner = THIS_MODULE;
        wrapper->ops.key = ca->key;
        wrapper->ops.flags = ca->flags;
        strncpy(wrapper->ops.name, "wr_", 4);
        strncpy(wrapper->ops.name + 3, ca->name, strlen(ca->name) + 1);
        
        // Set optional members
        if (ca->init)           wrapper->ops.init = tcp_ca_wrapper_init;
        if (ca->set_state)      wrapper->ops.set_state = tcp_ca_wrapper_set_state;
        if (ca->cwnd_event)     wrapper->ops.cwnd_event = tcp_ca_wrapper_cwnd_event;
        if (ca->pkts_acked)     wrapper->ops.pkts_acked = tcp_ca_wrapper_pkts_acked;
        if (ca->tso_segs_goal)  wrapper->ops.tso_segs_goal = tcp_ca_wrapper_tso_segs_goal;
        if (ca->get_info)       wrapper->ops.get_info = tcp_ca_wrapper_get_info;
        if (ca->sndbuf_expand)  wrapper->ops.sndbuf_expand = tcp_ca_wrapper_sndbuf_expand;
        if (ca->cong_control)   wrapper->ops.cong_control = tcp_ca_wrapper_cong_control;

        // Set inner congestion algorithm
        wrapper->inner = ca;

        // Create wrapper_holder object
        struct wrapper_holder* wrapper_holder = kmalloc(sizeof(*wrapper_holder), GFP_KERNEL);
        memset(wrapper_holder, 0, sizeof(*wrapper_holder));
        wrapper_holder->ops = wrapper;

        list_add_tail_rcu(&wrapper_holder->list, &wrappers_list);
        pr_info("add to the ops list: %s", wrapper->ops.name);

        spin_unlock(&wrappers_list_lock);
    }
    
    pr_info("register congestion control %s\n", ca->name);

    jprobe_return();

    return 0;
}

void jtcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
    spin_lock(&wrappers_list_lock);
    // TODO: delete wrapper from list and free
    spin_unlock(&wrappers_list_lock);

    pr_info("unregister congestion control %s\n", ca->name);

    jprobe_return();
}

static struct jprobe tcp_jprobe_reg = {
	.kp = {
		.symbol_name	= "tcp_register_congestion_control",
	},
	.entry	= jtcp_register_congestion_control,
};

static struct jprobe tcp_jprobe_unreg = {
	.kp = {
		.symbol_name	= "tcp_unregister_congestion_control",
	},
	.entry	= jtcp_unregister_congestion_control,
};

static int __init tcp_ca_wrapper_register(void)
{
    int ret = -ENOMEM;
    
    BUILD_BUG_ON(__same_type(tcp_register_congestion_control,
                             jtcp_register_congestion_control) == 0);
    BUILD_BUG_ON(__same_type(tcp_unregister_congestion_control,
                             jtcp_unregister_congestion_control) == 0);

    ret = register_jprobe(&tcp_jprobe_reg);
    if (ret)
        goto err1;

    ret = register_jprobe(&tcp_jprobe_unreg);
    if (ret)
        goto err2;

    pr_info("probes successfully registered");

    return tcp_register_congestion_control((struct tcp_congestion_ops*)&tcp_ca_wrapper);
    err1:
    err2:
    pr_err("probe registration unsuccessful");
    return ret;
}

static void __exit tcp_ca_wrapper_unregister(void)
{
    unregister_jprobe(&tcp_jprobe_reg);
    unregister_jprobe(&tcp_jprobe_unreg);
    tcp_unregister_congestion_control((struct tcp_congestion_ops*)&tcp_ca_wrapper);
}

module_init(tcp_ca_wrapper_register);
module_exit(tcp_ca_wrapper_unregister);

MODULE_AUTHOR("Alexander Kovalyov <cojuer@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP CA Wrapper");
