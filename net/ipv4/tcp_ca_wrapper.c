#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>

#include <net/tcp.h>
#include <net/congdb/tcp_ca_wrapper.h>
#include <net/congdb/congdb_manager.h>

#include <linux/kprobes.h>

static DEFINE_SPINLOCK(wrapper_list_lock);
static LIST_HEAD(wrapper_list);

static DEFINE_SPINLOCK(wrapper_ops_list_lock);
static LIST_HEAD(wrapper_ops_list);

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

struct ops_wrapper
{
    struct list_head list;
    struct tcp_congestion_ops* ops;
};

extern void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked);
extern u32 tcp_reno_ssthresh(struct sock *sk);
extern u32 tcp_reno_undo_cwnd(struct sock *sk);
static struct tcp_congestion_ops wr_reno = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "wr_reno",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
};

static void tcp_ca_wrapper_release(struct sock *sk);
u32 tcp_ca_wrapper_ssthresh(struct sock *sk);
void tcp_ca_wrapper_cong_avoid(struct sock *sk, u32 ack, u32 acked);
void tcp_ca_wrapper_in_ack_event(struct sock *sk, u32 flags);
u32 tcp_ca_wrapper_undo_cwnd(struct sock *sk);

static struct tcp_congestion_ops reno_wrapper = {
    .release       = tcp_ca_wrapper_release,
    .ssthresh	   = tcp_ca_wrapper_ssthresh,
    .cong_avoid	   = tcp_ca_wrapper_cong_avoid,
	.undo_cwnd	   = tcp_ca_wrapper_undo_cwnd,
    
    .flags         = TCP_CONG_NON_RESTRICTED,
	.owner		   = THIS_MODULE,
	.name		   = "tcp_ca_wrapper",
};

#define PRIV_CA_SIZE ICSK_CA_PRIV_SIZE / sizeof(u64)
#define PRIV_CA_ID PRIV_CA_SIZE - 1

struct sock_ca_stats* get_priv_ca_stats(struct sock *sk)
{
    return &((struct sock_ca_data**)inet_csk_ca(sk))[PRIV_CA_ID]->stats;
}

struct tcp_congestion_ops* get_priv_ca_ops(struct sock *sk)
{
    return ((struct sock_ca_data**)inet_csk_ca(sk))[PRIV_CA_ID]->ops;
}

static void tcp_ca_wrapper_init(struct sock *sk)
{
    pr_info("CAWR: init tcp_ca_wrapper\n");
    const char *ca_name = congdb_get_entry(sk->sk_rcv_saddr, sk->sk_daddr);

    struct sock_ca_data *sock_data;

    struct inet_connection_sock *icsk = inet_csk(sk);
    memset(icsk->icsk_ca_priv, 0, sizeof(icsk->icsk_ca_priv));
    ((struct sock_ca_data**)inet_csk_ca(sk))[PRIV_CA_ID] = kmalloc(sizeof(*sock_data), GFP_KERNEL);
    sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[PRIV_CA_ID];

    struct sock_ca_stats *stats = get_priv_ca_stats(sk);
    memset(stats, 0, sizeof(*stats));

    bool ca_found = false;
    
    // allocate name to find wrapper 
    // example: reno -> wr_reno
    char *ca_wr_name = kmalloc(4 + strlen(ca_name), GFP_KERNEL);
    strcpy(ca_wr_name, "wr_");
    strcat(ca_wr_name, ca_name);

    struct ops_wrapper *a;
    list_for_each_entry_rcu(a, &wrapper_ops_list, list) {
        if (strcmp(a->ops->name, ca_wr_name) == 0) {
            pr_info("CAWR: found ops for %s\n", ca_wr_name);
            inet_csk(sk)->icsk_ca_ops = a->ops;
            ca_found = true;
        }
    }

    kfree(ca_wr_name);

    struct tcp_congestion_ops *e;
    list_for_each_entry_rcu(e, &wrapper_list, list) {
		if (strcmp(e->name, ca_name) == 0) {
            sock_data->ops = e;
        }
    }

    if (!ca_found)
    {
        inet_csk(sk)->icsk_ca_ops = &reno_wrapper;
        sock_data->ops = &wr_reno;
        pr_info("CAWR: ops not found, using reno\n");
    }

    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
    if (ops->init)
        ops->init(sk);
}

extern void congdb_aggregate_stats(uint32_t loc_ip, uint32_t rem_ip, void *stats);
static void tcp_ca_wrapper_release(struct sock *sk)
{
    pr_info("release private sock data");
    pr_info("acks number: %u", get_priv_ca_stats(sk)->acks_num);
    pr_info("loss number: %u", get_priv_ca_stats(sk)->loss_num);
    pr_info("rtt size: %u", get_priv_ca_stats(sk)->rtt);
    congdb_aggregate_stats(sk->sk_rcv_saddr, sk->sk_daddr, get_priv_ca_stats(sk));

    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
    if (ops->release)
        ops->release(sk);

    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[PRIV_CA_ID];
    kfree(sock_data);
    pr_info("session ended");
}

u32 tcp_ca_wrapper_ssthresh(struct sock *sk)
{
    if (get_priv_ca_ops(sk)->ssthresh)
        return get_priv_ca_ops(sk)->ssthresh(sk);
    else return tcp_reno_ssthresh(sk);
}

void tcp_ca_wrapper_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    if (get_priv_ca_ops(sk)->cong_avoid)
        get_priv_ca_ops(sk)->cong_avoid(sk, ack, acked);
    else tcp_reno_cong_avoid(sk, ack, acked);
}

void tcp_ca_wrapper_set_state(struct sock *sk, u8 new_state)
{
    get_priv_ca_ops(sk)->set_state(sk, new_state);
}

void tcp_ca_wrapper_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
    get_priv_ca_ops(sk)->cwnd_event(sk, ev);
}

void tcp_ca_wrapper_in_ack_event(struct sock *sk, u32 flags)
{
    get_priv_ca_stats(sk)->acks_num += 1;

    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
    if (ops->in_ack_event)
        ops->in_ack_event(sk, flags);
}

u32 tcp_ca_wrapper_undo_cwnd(struct sock *sk)
{
    get_priv_ca_stats(sk)->loss_num += 1;
    
    if (get_priv_ca_ops(sk)->undo_cwnd)
        return get_priv_ca_ops(sk)->undo_cwnd(sk);
    else return tcp_reno_undo_cwnd(sk);
}

void tcp_ca_wrapper_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
    get_priv_ca_ops(sk)->pkts_acked(sk, sample);
}

u32 tcp_ca_wrapper_tso_segs_goal(struct sock *sk)
{
    return get_priv_ca_ops(sk)->tso_segs_goal(sk);
}

u32 tcp_ca_wrapper_sndbuf_expand(struct sock *sk)
{
    return get_priv_ca_ops(sk)->sndbuf_expand(sk);
}

void tcp_ca_wrapper_cong_control(struct sock *sk, const struct rate_sample *rs)
{
    get_priv_ca_ops(sk)->cong_control(sk, rs);
}

size_t tcp_ca_wrapper_get_info(struct sock *sk, u32 ext, int *attr,
           union tcp_cc_info *info)
{
    return get_priv_ca_ops(sk)->get_info(sk, ext, attr, info);
}

static struct tcp_congestion_ops tcp_ca_wrapper __read_mostly = {
    .init		   = tcp_ca_wrapper_init,
    .release       = tcp_ca_wrapper_release,
    .ssthresh	   = tcp_ca_wrapper_ssthresh,
    .cong_avoid	   = tcp_ca_wrapper_cong_avoid,
	.undo_cwnd	   = tcp_ca_wrapper_undo_cwnd,

	.owner		   = THIS_MODULE,
	.name		   = "tcp_ca_wrapper",
};

int jtcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
    if (!ca->ssthresh || !ca->undo_cwnd ||
	    !(ca->cong_avoid || ca->cong_control)) {
        jprobe_return();
        return -EINVAL;
    }
    
    spin_lock(&wrapper_list_lock);
    
    // copy to the new structure
    struct tcp_congestion_ops* ca_copy = kmalloc(sizeof(*ca_copy), GFP_KERNEL);
    *ca_copy = *ca;

    // FIXME: check if was already registered
    list_add_tail_rcu(&ca_copy->list, &wrapper_list);
    pr_info("add to the list: %s", ca_copy->name);

    spin_unlock(&wrapper_list_lock);

    if (strcmp(ca->name, "tcp_ca_wrapper") != 0) {
        spin_lock(&wrapper_ops_list_lock);

        // create correct wrapper ops

        struct ops_wrapper* ops_wrapper = kmalloc(sizeof(*ops_wrapper), GFP_KERNEL);
        struct tcp_congestion_ops* wrap_ops = kmalloc(sizeof(*wrap_ops), GFP_KERNEL);
        
        memset(ops_wrapper, 0, sizeof(*ops_wrapper));
        memset(wrap_ops, 0, sizeof(*wrap_ops));

        // required
        wrap_ops->release = tcp_ca_wrapper_release;  
        wrap_ops->cong_avoid = tcp_ca_wrapper_cong_avoid;
        wrap_ops->ssthresh = tcp_ca_wrapper_ssthresh;
        wrap_ops->in_ack_event = tcp_ca_wrapper_in_ack_event;
        wrap_ops->undo_cwnd = tcp_ca_wrapper_undo_cwnd;
        wrap_ops->owner = THIS_MODULE;
        wrap_ops->key = ca->key;
        wrap_ops->flags = ca->flags;
        strncpy(wrap_ops->name, "wr_", 4);
        strncpy(wrap_ops->name + 3, ca->name, strlen(ca->name) + 1);
        
        // optional
        if (ca->init) wrap_ops->init = tcp_ca_wrapper_init;
        if (ca->set_state) wrap_ops->set_state = tcp_ca_wrapper_set_state;
        if (ca->cwnd_event) wrap_ops->cwnd_event = tcp_ca_wrapper_cwnd_event;
        if (ca->pkts_acked) wrap_ops->pkts_acked = tcp_ca_wrapper_pkts_acked;
        if (ca->tso_segs_goal) wrap_ops->tso_segs_goal = tcp_ca_wrapper_tso_segs_goal;
        if (ca->get_info) wrap_ops->get_info = tcp_ca_wrapper_get_info;
        if (ca->sndbuf_expand) wrap_ops->sndbuf_expand = tcp_ca_wrapper_sndbuf_expand;
        if (ca->cong_control) wrap_ops->cong_control = tcp_ca_wrapper_cong_control;

        ops_wrapper->ops = wrap_ops;

        list_add_tail_rcu(&ops_wrapper->list, &wrapper_ops_list);
        pr_info("add to the ops list: %s", wrap_ops->name);

        spin_unlock(&wrapper_ops_list_lock);
    }
    
    pr_info("register congestion control %s\n", ca->name);

    jprobe_return();

    return 0;
}

void jtcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
    spin_lock(&wrapper_list_lock);
    
    pr_info("del from the list: %s", ca->name);
	spin_unlock(&wrapper_list_lock);

    spin_lock(&wrapper_ops_list_lock);

    spin_unlock(&wrapper_ops_list_lock);

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

    return tcp_register_congestion_control(&tcp_ca_wrapper);
    err1:
    err2:
    pr_err("probe registration unsuccessful");
    return ret;
}

static void __exit tcp_ca_wrapper_unregister(void)
{
    unregister_jprobe(&tcp_jprobe_reg);
    unregister_jprobe(&tcp_jprobe_unreg);
    tcp_unregister_congestion_control(&tcp_ca_wrapper);
}

module_init(tcp_ca_wrapper_register);
module_exit(tcp_ca_wrapper_unregister);

MODULE_AUTHOR("Alexander Kovalyov <cojuer@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP CA Wrapper");
