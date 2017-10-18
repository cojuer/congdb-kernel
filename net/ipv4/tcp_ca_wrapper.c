#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>

#include <net/tcp.h>
#include <net/congdb/tcp_ca_wrapper.h>

#include <linux/kprobes.h>

struct sock_ca_stats
{
    u32 rtt;
    u32 bandwidth;
    u32 loss;
    u32 duration;
};

struct sock_ca_data
{
    struct tcp_congestion_ops* ops;
    struct sock_ca_stats stats;
};

static void tcp_ca_wrapper_init(struct sock *sk)
{
    pr_err("init\n");
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    pr_err("kmalloc data\n");
    sock_data = kmalloc(sizeof(*sock_data), GFP_KERNEL);
    bool ecn_ca = false;
    pr_err("get_key\n");
    u32 key = tcp_ca_get_key_by_name("cubic", &ecn_ca);
    pr_err("The key is %u", key);
    sock_data->ops = IMPORTED(tcp_ca_find_key)(key);
    pr_err("init cubic");
    sock_data->ops->init(sk);
}

static void tcp_ca_wrapper_release(struct sock *sk)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    if (ops->release)
        ops->release(sk);

    kfree(sock_data);
}

u32 tcp_ca_wrapper_ssthresh(struct sock *sk)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    
    
    return ops->ssthresh(sk);
}

void tcp_ca_wrapper_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    ops->cong_avoid(sk, ack, acked);
}

void tcp_ca_wrapper_set_state(struct sock *sk, u8 new_state)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    ops->set_state(sk, new_state);
}

void tcp_ca_wrapper_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    ops->cwnd_event(sk, ev);
}

void tcp_ca_wrapper_in_ack_event(struct sock *sk, u32 flags)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    ops->in_ack_event(sk, flags);
}

u32 tcp_ca_wrapper_undo_cwnd(struct sock *sk)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    return ops->undo_cwnd(sk);
}

void tcp_ca_wrapper_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    ops->pkts_acked(sk, sample);
}

u32 tcp_ca_wrapper_tso_segs_goal(struct sock *sk)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    return ops->tso_segs_goal(sk);
}

u32 tcp_ca_wrapper_sndbuf_expand(struct sock *sk)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    return ops->sndbuf_expand(sk);
}

void tcp_ca_wrapper_cong_control(struct sock *sk, const struct rate_sample *rs)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    ops->cong_control(sk, rs);
}

size_t tcp_ca_wrapper_get_info(struct sock *sk, u32 ext, int *attr,
           union tcp_cc_info *info)
{
    struct sock_ca_data *sock_data = ((struct sock_ca_data**)inet_csk_ca(sk))[11];
    struct tcp_congestion_ops *ops = sock_data->ops;
    return ops->get_info(sk, ext, attr, info);
}

static struct tcp_congestion_ops tcp_ca_wrapper __read_mostly = {
    .init		   = tcp_ca_wrapper_init,
    //.release       = tcp_ca_wrapper_release,
    .ssthresh	   = tcp_ca_wrapper_ssthresh,
    .cong_avoid	   = tcp_ca_wrapper_cong_avoid,
    .set_state     = tcp_ca_wrapper_set_state,
    .cwnd_event	   = tcp_ca_wrapper_cwnd_event,
    //.in_ack_event  = tcp_ca_wrapper_in_ack_event,
	.undo_cwnd	   = tcp_ca_wrapper_undo_cwnd,
    .pkts_acked	   = tcp_ca_wrapper_pkts_acked,
    //.tso_segs_goal = tcp_ca_wrapper_tso_segs_goal,
    //.get_info      = tcp_ca_wrapper_get_info,

	.owner		   = THIS_MODULE,
	.name		   = "tcp_ca_wrapper",
};

int jtcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
    pr_info("register congestion control %s\n", ca->name);
    
    jprobe_return();

    return 0;
}

void jtcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
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
