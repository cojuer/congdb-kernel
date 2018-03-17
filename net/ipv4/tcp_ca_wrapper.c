#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>

#include <net/tcp.h>
#include <net/congdb/tcp_ca_wrapper.h>
#include <net/congdb/congdb_manager.h>

#include <linux/kprobes.h>

static DEFINE_SPINLOCK(inner_cas_list_lock);
static LIST_HEAD(inner_cas_list);

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

struct ops_wrapper
{
    struct list_head list;
    struct tcp_congestion_ops* ops;
};

// create copy of standard reno algorithm
extern void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked);
extern u32 tcp_reno_ssthresh(struct sock *sk);
extern u32 tcp_reno_undo_cwnd(struct sock *sk);

static struct tcp_congestion_ops reno = {
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

static struct tcp_congestion_ops wr_reno = {
    .release       = tcp_ca_wrapper_release,
    .ssthresh	   = tcp_ca_wrapper_ssthresh,
    .cong_avoid	   = tcp_ca_wrapper_cong_avoid,
	.undo_cwnd	   = tcp_ca_wrapper_undo_cwnd,
    
    .flags         = TCP_CONG_NON_RESTRICTED,
	.owner		   = THIS_MODULE,
	.name		   = "wr_reno",
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

struct tcp_congestion_ops* get_priv_ca_ops(struct sock *sk)
{
    struct sock_ca_data *data = get_priv_ca_data(sk);
    if (!data) 
    {
        pr_err("CAWR: data is NULL");
        return NULL;
    }
    return data->ops;
}

static void tcp_ca_wrapper_init(struct sock *sk)
{
    pr_info("CAWR: init tcp_ca_wrapper");
    const char *inner_ca_name = congdb_get_entry(sk->sk_rcv_saddr, sk->sk_daddr);

    // allocate memory for socket data
    ((struct sock_ca_data**)inet_csk_ca(sk))[PRIV_CA_ID] = kmalloc(sizeof(struct sock_ca_data), GFP_KERNEL);
    struct sock_ca_data *sock_data = get_priv_ca_data(sk);

    // set all statiscits to zeroes
    struct sock_ca_stats *stats = get_priv_ca_stats(sk);
    memset(stats, 0, sizeof(*stats));

    bool wrapper_found = false;
    bool inner_ca_found = false;
    
    // allocate name to find wrapper 
    // example: reno -> wr_reno
    char *wrapper_name = kmalloc(4 + strlen(inner_ca_name), GFP_KERNEL);
    strcpy(wrapper_name, "wr_");
    strcat(wrapper_name, inner_ca_name);

    // look for wrapper
    struct ops_wrapper *a;
    list_for_each_entry_rcu(a, &wrappers_list, list) {
        if (strcmp(a->ops->name, wrapper_name) == 0) {
            pr_info("CAWR: use wrapper \"%s\"", wrapper_name);
            inet_csk(sk)->icsk_ca_ops = a->ops;
            wrapper_found = true;
        }
    }
    kfree(wrapper_name);

    // look for inner ca
    if (wrapper_found) {
        struct tcp_congestion_ops *e;
        list_for_each_entry_rcu(e, &inner_cas_list, list) {
            if (strcmp(e->name, inner_ca_name) == 0) {
                pr_info("CAWR: use inner \"%s\"", inner_ca_name);
                sock_data->ops = e;
                inner_ca_found = true;
            }
        }
    }

    // set reno if wrapper or inner ca not found
    if (!wrapper_found || !inner_ca_found)
    {
        pr_err("CAWR: wrapper or inner ca not found, using reno");
        inet_csk(sk)->icsk_ca_ops = &wr_reno;
        sock_data->ops = &reno;
    }

    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
    if (ops->init)
        ops->init(sk);
}

extern void congdb_aggregate_stats(uint32_t loc_ip, uint32_t rem_ip, void *stats);
static void tcp_ca_wrapper_release(struct sock *sk)
{
    struct sock_ca_data *sock_data = get_priv_ca_data(sk);
    if (sock_data == NULL)
    {
        pr_err("CAWR: sock data has been released");
        return;
    }

    // write smoothed rtt into stats
    u32 rtt = ((struct tcp_sock*)sk)->srtt_us >> 3;
    get_priv_ca_stats(sk)->rtt = rtt;

    // aggregate statistics
    congdb_aggregate_stats(sk->sk_rcv_saddr, sk->sk_daddr, get_priv_ca_stats(sk));

    pr_info("CAWR: release private sock data");

    // release inner congestion algorithm
    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
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

    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
    if (ops) 
    {
        return ops->ssthresh(sk);
    }
    else 
    {
        pr_err("CAWR: ops invalid");
        return 0;
    }
}

void tcp_ca_wrapper_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
    if (ops)
    { 
        ops->cong_avoid(sk, ack, acked);
    }
    else 
    {
        pr_err("CAWR: ops invalid");
    }
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
    struct sock_ca_stats* stats = get_priv_ca_stats(sk);
    if (stats) 
        stats->acks_num += 1;

    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
    if (ops && ops->in_ack_event)
        ops->in_ack_event(sk, flags);
}

u32 tcp_ca_wrapper_undo_cwnd(struct sock *sk)
{
    struct tcp_congestion_ops *ops = get_priv_ca_ops(sk);
    if (ops)
    {
        return ops->undo_cwnd(sk);
    }
    else 
    {
        pr_err("CAWR: ops invalid");
        return 0;
    }
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
    
    spin_lock(&inner_cas_list_lock);
    
    // copy to the new structure
    struct tcp_congestion_ops* ca_copy = kmalloc(sizeof(*ca_copy), GFP_KERNEL);
    *ca_copy = *ca;

    // FIXME: check if was already registered
    list_add_tail_rcu(&ca_copy->list, &inner_cas_list);
    pr_info("add to the list: %s", ca_copy->name);

    spin_unlock(&inner_cas_list_lock);

    if (strcmp(ca->name, "tcp_ca_wrapper") != 0) {
        spin_lock(&wrappers_list_lock);

        // create correct wrapper ops

        struct ops_wrapper* ops_wrapper = kmalloc(sizeof(*ops_wrapper), GFP_KERNEL);
        struct tcp_congestion_ops* wrapper = kmalloc(sizeof(*wrapper), GFP_KERNEL);
        
        memset(ops_wrapper, 0, sizeof(*ops_wrapper));
        memset(wrapper, 0, sizeof(*wrapper));

        // required
        wrapper->release = tcp_ca_wrapper_release;  
        wrapper->cong_avoid = tcp_ca_wrapper_cong_avoid;
        wrapper->ssthresh = tcp_ca_wrapper_ssthresh;
        wrapper->in_ack_event = tcp_ca_wrapper_in_ack_event;
        wrapper->undo_cwnd = tcp_ca_wrapper_undo_cwnd;
        wrapper->owner = THIS_MODULE;
        wrapper->key = ca->key;
        wrapper->flags = ca->flags;
        strncpy(wrapper->name, "wr_", 4);
        strncpy(wrapper->name + 3, ca->name, strlen(ca->name) + 1);
        
        // optional
        if (ca->init) wrapper->init = tcp_ca_wrapper_init;
        if (ca->set_state) wrapper->set_state = tcp_ca_wrapper_set_state;
        if (ca->cwnd_event) wrapper->cwnd_event = tcp_ca_wrapper_cwnd_event;
        if (ca->pkts_acked) wrapper->pkts_acked = tcp_ca_wrapper_pkts_acked;
        if (ca->tso_segs_goal) wrapper->tso_segs_goal = tcp_ca_wrapper_tso_segs_goal;
        if (ca->get_info) wrapper->get_info = tcp_ca_wrapper_get_info;
        if (ca->sndbuf_expand) wrapper->sndbuf_expand = tcp_ca_wrapper_sndbuf_expand;
        if (ca->cong_control) wrapper->cong_control = tcp_ca_wrapper_cong_control;

        ops_wrapper->ops = wrapper;

        list_add_tail_rcu(&ops_wrapper->list, &wrappers_list);
        pr_info("add to the ops list: %s", wrapper->name);

        spin_unlock(&wrappers_list_lock);
    }
    
    pr_info("register congestion control %s\n", ca->name);

    jprobe_return();

    return 0;
}

void jtcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
    spin_lock(&inner_cas_list_lock);
    
    pr_info("del from the list: %s", ca->name);
	spin_unlock(&inner_cas_list_lock);

    spin_lock(&wrappers_list_lock);

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
