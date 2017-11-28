#include <net/congdb/congdb_manager.h>

#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <net/genetlink.h>

enum congdb_nl_cmds {
    CONGDB_C_UNSPEC,

    CONGDB_C_ADD_ENTRY,
    CONGDB_C_DEL_ENTRY,
    CONGDB_C_CLEAR_ENTRIES,

    CONGDB_C_LIST_ENTRIES,

    // used to verify nl commands
    __CONGDB_C_MAX,
    CONGDB_C_MAX = __CONGDB_C_MAX - 1
};

enum congdb_nl_attrs {
    CONGDB_A_UNSPEC,
    
    CONGDB_A_LOC_IP,
    CONGDB_A_REM_IP,

    CONGDB_A_LOC_MASK,
    CONGDB_A_REM_MASK,

    CONGDB_A_PRIORITY,

    CONGDB_A_CA,

    CONGDB_A_ACKS_NUM,
    CONGDB_A_LOSS_NUM,
    CONGDB_A_RTT,

    // used to verify nl attributes
    __CONGDB_A_MAX,
    CONGDB_A_MAX = __CONGDB_A_MAX - 1
};

static struct genl_family congdb_genl_fam = {
    .hdrsize = 0,
    .name = "CONGDB_MANAGER",
    .version = 1,
    .maxattr = CONGDB_A_MAX,
};

/* Checks payload of the given attribute.
 * Returns pointer to the payload,
 *  when it contains a valid identifier string:
 *   - consists of letters, digits and blanks,
 *   - does not start with a digit, and
 *   - is shorter than 50 symbols.
 * Returns NULL otherwise.
 */
static char* nla_get_id(struct nlattr *attr)
{
    char *val = (char*)nla_data(attr), *p = val;
    if (!p || !*p) return NULL;
    if (!isalpha(*p) && *p != '_') return NULL;
    while (*++p) if (!isalnum(*p) && *p != '_') return NULL;
    if (p - val > 50) return NULL;
    return (char*) nla_data(attr);
}

/* Converts ipv4 string attribute to uint32_t.
 * Returns 0, if the given string is invalid.
 */
static uint32_t nla_get_ip(struct nlattr *attr)
{
    char *ip_str = (char*) nla_data(attr);
    uint32_t ip;
    if (!in4_pton(ip_str, -1, (u8*)&ip, -1, NULL))
        return 0;
    return ip;
}

static int nla_put_congdb_data(struct sk_buff *skb, struct congdb_data *data)
{
    size_t i;
    for(i = 0; i < data->size; ++i) {
        if (nla_put_u32(skb, CONGDB_A_LOC_IP, data->entries[i].id.loc_ip))
            return -EFBIG;
        if (nla_put_u32(skb, CONGDB_A_LOC_MASK, data->entries[i].id.loc_mask))
            return -EFBIG;
        if (nla_put_u32(skb, CONGDB_A_REM_IP, data->entries[i].id.rem_ip))
            return -EFBIG;
        if (nla_put_u32(skb, CONGDB_A_REM_MASK, data->entries[i].id.rem_mask))
            return -EFBIG;
        if (nla_put_u8(skb, CONGDB_A_PRIORITY, data->entries[i].id.priority))
            return -EFBIG;
        if (nla_put_string(skb, CONGDB_A_CA, data->entries[i].ca_name))
            return -EFBIG;
        if (nla_put_u32(skb, CONGDB_A_ACKS_NUM, data->entries[i].stats.acks_num))
            return -EFBIG;
        if (nla_put_u32(skb, CONGDB_A_LOSS_NUM, data->entries[i].stats.loss_num))
            return -EFBIG;
        if (nla_put_u32(skb, CONGDB_A_RTT, data->entries[i].stats.rtt))
            return -EFBIG;
    }
    return 0;
}

static int reply_congdb_data(struct genl_info *query_info,
                             struct congdb_data *data)
{
    struct sk_buff *reply;
    void *genl_hdr;

    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!reply) {
        pr_warn("CONGDB: no memory to reply\n");
        return -ENOMEM;
    }

    genl_hdr = genlmsg_put_reply(reply, query_info, &congdb_genl_fam,
                                 0, CONGDB_C_LIST_ENTRIES);
    if (!genl_hdr || nla_put_congdb_data(reply, data)) {
        pr_warn("CONGDB: failed to compose reply\n");
        kfree(reply);
        return -EFBIG;
    }

    genlmsg_end(reply, genl_hdr);
    if (genlmsg_reply(reply, query_info)) {
        pr_warn("CONGDB: failed to send reply\n");
        kfree(reply);
        return -EIO;
    }
    return 0;
}

static int extract_tcp_data(struct nlattr **attrs, struct rule_id *id)
{
    uint32_t loc_ip, loc_mask;
    uint32_t rem_ip, rem_mask;
    uint8_t priority;

    if (!attrs[CONGDB_A_LOC_IP]) {
        pr_warn("CONGDB: invalid local ip number\n");
        return -EINVAL;
    }
    loc_ip = nla_get_u32(attrs[CONGDB_A_LOC_IP]);
    if (!attrs[CONGDB_A_LOC_MASK]) {
        pr_warn("CONGDB: local mask not provided\n");
        loc_mask = UINT_MAX;
    } 
    else {
        loc_mask = nla_get_u32(attrs[CONGDB_A_LOC_MASK]);
    }
    if (!attrs[CONGDB_A_REM_IP]) {
        pr_warn("CONGDB: invalid remote ip number\n");
        return -EINVAL;
    }
    rem_ip = nla_get_u32(attrs[CONGDB_A_REM_IP]);
    if (!attrs[CONGDB_A_REM_MASK]) {
        pr_warn("CONGDB: remote mask not provided\n");
        rem_mask = UINT_MAX;
    } 
    else {
        rem_mask = nla_get_u32(attrs[CONGDB_A_REM_MASK]);
    }
    if (!attrs[CONGDB_A_PRIORITY]) {
        pr_warn("CONGDB: priority not provided\n");
        priority = 0;
    } 
    else {
        priority = nla_get_u8(attrs[CONGDB_A_PRIORITY]);
    }

    id->loc_ip = loc_ip;
    id->loc_mask = loc_mask;
    id->rem_ip = rem_ip;
    id->rem_mask = rem_mask;
    id->priority = priority;

    return 0;
}

static int cmd_op_on_database(struct sk_buff *skb, struct genl_info *info)
{
    struct nlattr **attrs = info->attrs;

    switch(info->genlhdr->cmd) {
        case CONGDB_C_ADD_ENTRY:
            {
                char* name;
                name = nla_get_id(attrs[CONGDB_A_CA]);
                if (!name) {
                    pr_warn("CONGDB: invalid congestion algorithm name\n");
                    return -EINVAL;
                }
                struct rule_id id;
                if (extract_tcp_data(attrs, &id)) {
                    return -1;
                }
                return congdb_add_entry(&id, name);
            }
        case CONGDB_C_DEL_ENTRY:
            {
                struct rule_id id;
                if (extract_tcp_data(attrs, &id)) {
                    return -1;
                }
                return congdb_del_entry(&id);
            }
        case CONGDB_C_CLEAR_ENTRIES:
            {
                congdb_clear_entries();
                return 0;
            }
        case CONGDB_C_LIST_ENTRIES:
            {
                struct congdb_data *data;
                int result;
                
                data = congdb_list_entries();
                if (!data) {
                    pr_err("CONGDB: failed to get congdb data\n");
                    return -EFBIG;
                }
                
                result = reply_congdb_data(info, data);
                congdb_data_free(data);
                return result;
            }
        default:
            pr_warn("CONGDB: unspecified command\n");
    }
    return 0;
}

static struct nla_policy congdb_genl_policy[CONGDB_A_MAX + 1] = {
    [CONGDB_A_CA] = {.type = NLA_NUL_STRING, .len = 15},
    [CONGDB_A_LOC_IP] = {.type = NLA_U32},
    [CONGDB_A_LOC_MASK] = {.type = NLA_U32},
    [CONGDB_A_REM_IP] = {.type = NLA_U32},
    [CONGDB_A_REM_MASK] = {.type = NLA_U32},
    [CONGDB_A_PRIORITY] = {.type = NLA_U8},
    [CONGDB_A_ACKS_NUM] = {.type = NLA_U32},
    [CONGDB_A_LOSS_NUM] = {.type = NLA_U32},
    [CONGDB_A_RTT] = {.type = NLA_U32},
};

static const struct genl_ops congdb_manager_ops[] = {
    {
        .cmd = CONGDB_C_ADD_ENTRY,
        .policy = congdb_genl_policy,
        .doit = cmd_op_on_database,
    },
    {
        .cmd = CONGDB_C_DEL_ENTRY,
        .policy = congdb_genl_policy,
        .doit = cmd_op_on_database,
    },
    {
        .cmd = CONGDB_C_CLEAR_ENTRIES,
        .policy = congdb_genl_policy,
        .doit = cmd_op_on_database,
    },
    {
        .cmd = CONGDB_C_LIST_ENTRIES,
        .policy = congdb_genl_policy,
        .doit = cmd_op_on_database,
    }
};

static int __init congdb_manager_init(void)
{
    congdb_genl_fam.ops = congdb_manager_ops;
    congdb_genl_fam.n_ops = CONGDB_C_MAX + 1;
    if (genl_register_family(&congdb_genl_fam)) {
        pr_err("Congestion database: can not register netlink family\n");
        return 1;
    }

    //rcu_assign_pointer(congdb_tun_ops, &tun_ops);
    synchronize_rcu();

    return 0;
}

static void __exit congdb_manager_exit(void)
{
    //rcu_assign_pointer(congdb_tun_ops, &congdb_tunnel_default);
    synchronize_rcu();

    genl_unregister_family(&congdb_genl_fam);
    congdb_clear_entries();
}

module_init(congdb_manager_init);
module_exit(congdb_manager_exit);

MODULE_AUTHOR("Kovalyov Alexander");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Congestion database");
MODULE_VERSION("0.1");