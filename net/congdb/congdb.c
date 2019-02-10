#include <net/congdb/congdb_manager.h>

#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/string.h>

static DEFINE_SPINLOCK(data_lock);
static DEFINE_HASHTABLE(ip_hash_table, 5);
static LIST_HEAD(entries);

struct congdb_entry {
    struct list_head lnode;
    struct rule_id id;
    struct rule_stats stats;
    char* ca_name;
};

bool match_ipv4(uint32_t ip_to_test, uint32_t ip, uint32_t mask)
{
    return ((ip_to_test & mask) == (ip & mask));
}

/**
 * Find entry by given identifier
 */
static struct congdb_entry* __find_entry(struct rule_id *id)
{
    struct congdb_entry *entry;
    list_for_each_entry(entry, &entries, lnode) {
        if (match_ipv4(entry->id.loc_ip, id->loc_ip, id->loc_mask) &&
            match_ipv4(entry->id.rem_ip, id->rem_ip, id->rem_mask) &&
            entry->id.priority == id->priority) return entry;
    }
    return NULL;
}

/**
 * Add new entry
 */
int congdb_add_entry(struct rule_id *id, char* ca)
{
    int status = -1;
    spin_lock(&data_lock);
    if (__find_entry(id)) {
        // TODO: write all data in error
        pr_err("CONGDB: entry already exists\n");
    } else {
        struct congdb_entry *new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC);
        char* ca_name = kmalloc(strlen(ca) + 1, GFP_ATOMIC);

        if (new_entry && ca_name) {
            new_entry->ca_name = strcpy(ca_name, ca);
            new_entry->id = *id;
            memset(&new_entry->stats, 0, sizeof(new_entry->stats));
            list_add(&new_entry->lnode, &entries);
            status = 0;
        } else {
            pr_err("CONGDB: cannot allocate memory for new entry\n");
            kfree(new_entry);
            kfree(ca_name);
        }
    }
    spin_unlock(&data_lock);
    return status;
}

/**
 * Set CA name for entry with given identifier
 * Also reset all statistics.
 */
int congdb_set_entry(struct rule_id *id, char* ca)
{
    int status = -1;
    struct congdb_entry *entry;
    spin_lock(&data_lock);

    entry = __find_entry(id); 
    if (!entry) {
        pr_err("CONGDB: no entry with such identifier\n");
    } else {
        char* ca_mem = kmalloc(strlen(ca) + 1, GFP_ATOMIC);
        if (ca_mem) {
            kfree(entry->ca_name);
            entry->ca_name = strcpy(ca_mem, ca);
            memset(&entry->stats, 0, sizeof(entry->stats));
            status = 0;
        } else {
            pr_err("CONGDB: cannot allocate memory for new entry\n");
            kfree(ca_mem);
        }
    }
    spin_unlock(&data_lock);
    return status;
}

/**
 * Delete given entry
 */
void __del_entry(struct congdb_entry *entry)
{
    list_del(&entry->lnode);
    kfree(entry->ca_name);
    kfree(entry);
}

/**
 * Delete entry with given identifier
 */
int congdb_del_entry(struct rule_id *id)
{
    int status = -1;
    spin_lock(&data_lock);

    struct congdb_entry *entry = __find_entry(id);
    if (!entry) {
        // TODO: write all data in error
        pr_err("CONGDB: entry does not exist\n");
    } else {
        __del_entry(entry);
        status = 0;
    }
    spin_unlock(&data_lock);
    return status;
}

const char* congdb_get_entry(uint32_t loc_ip, uint32_t rem_ip)
{
    int status = -1;

    struct rule_id id = {
        .loc_ip = loc_ip,
        .loc_mask = UINT_MAX,
        .rem_ip = rem_ip,
        .rem_mask = UINT_MAX,
        .priority = 0
    };

    spin_lock(&data_lock);

    char* ca = NULL;
    struct congdb_entry *entry = __find_entry(&id);
    if (!entry) {
        pr_err("CONGDB: entry does not exist\n");
        spin_unlock(&data_lock);
        return "reno";
    } else {
        ca = entry->ca_name;
        spin_unlock(&data_lock);
        pr_warn("CONGDB: entry found %s\n", ca);
        // FIXME: check if congestion is available
        return ca;
    }
    spin_unlock(&data_lock);
    return ca;
}

void congdb_aggregate_stats(uint32_t loc_ip, uint32_t rem_ip, void *stats)
{
    struct rule_stats *stats_to_agg = (struct rule_stats*)stats;
    struct rule_id id = {
        .loc_ip = loc_ip,
        .loc_mask = UINT_MAX,
        .rem_ip = rem_ip,
        .rem_mask = UINT_MAX,
        .priority = 0
    };

    spin_lock(&data_lock);

    char* ca = NULL;
    struct congdb_entry *entry = __find_entry(&id);
    if (!entry) {
        pr_err("CONGDB: no rule for socket statistics");
    } else {
        if (entry->stats.acks_num == 0 &&
            entry->stats.loss_num == 0 &&
            entry->stats.rtt == 0) {
            entry->stats.acks_num = stats_to_agg->acks_num;
            entry->stats.loss_num = stats_to_agg->loss_num;
            entry->stats.rtt = stats_to_agg->rtt;
        } else if (stats_to_agg->acks_num > 50) {
            entry->stats.acks_num = entry->stats.acks_num * 9 / 10 + stats_to_agg->acks_num / 10;
            entry->stats.loss_num = entry->stats.loss_num * 9 / 10 + stats_to_agg->loss_num / 10;
            entry->stats.rtt = entry->stats.rtt * 9 / 10 + stats_to_agg->rtt / 10;
        }
        pr_info("CONGDB: statistics aggregation succeded");
    }
    spin_unlock(&data_lock);
}
EXPORT_SYMBOL_GPL(congdb_aggregate_stats);

void congdb_clear_entries()
{
    struct congdb_entry *entry, *tmp;
    spin_lock(&data_lock);
    list_for_each_entry_safe(entry, tmp, &entries, lnode) {
        __del_entry(entry);
    }
    INIT_LIST_HEAD(&entries);
    spin_unlock(&data_lock);
}


struct congdb_data* congdb_data_alloc(size_t size)
{
    struct congdb_data* data;
    data = kzalloc(sizeof(size_t) + size * sizeof(struct congdb_entry_data),
                   GFP_ATOMIC);
    if (!data) {
        pr_err("CONGDB: can not allocate memory for congdb data\n");
        return NULL;
    }
    data->size = size;
    return data;
}

// FIXME: probably not deleting ca names
void congdb_data_free(struct congdb_data *data)
{
    kfree(data);
}

struct congdb_data* congdb_list_entries()
{
    struct congdb_data *data = NULL;
    struct congdb_entry *entry;
    size_t index = 0;

    spin_lock(&data_lock);
    list_for_each_entry(entry, &entries, lnode) ++index;
    data = congdb_data_alloc(index);
    if (data) {
        list_for_each_entry_reverse(entry, &entries, lnode) {
            char *name = kmalloc(strlen(entry->ca_name) + 1,
                                  GFP_ATOMIC);
            if (name) {
                --index;
                data->entries[index].ca_name = strcpy(name, entry->ca_name);
                data->entries[index].id = entry->id;
                data->entries[index].stats = entry->stats;
            } else {
                pr_err("CONGDB: cannot allocate memory for entries list\n");
                congdb_data_free(data);
                data = NULL;
                break;
            }
        }
    }
    spin_unlock(&data_lock);
    return data;
}

struct congdb_entry_data* congdb_get_entry_nl(struct rule_id *id)
{
    struct congdb_entry *entry;
    struct congdb_entry_data *entry_copy;

    spin_lock(&data_lock);

    entry = __find_entry(id);
    entry_copy = kmalloc(sizeof(struct congdb_entry_data), GFP_ATOMIC);
    char *name = kmalloc(strlen(entry->ca_name) + 1, GFP_ATOMIC);
    if (entry_copy && name) {
        entry_copy->ca_name = strcpy(name, entry->ca_name);
        entry_copy->id = entry->id;
        entry_copy->stats = entry->stats;
    } else {
        pr_err("CADB: could not allocate memory for entry\n");
        kfree(name);
        kfree(entry_copy);
        entry_copy = NULL;
    }

    spin_unlock(&data_lock);
    return entry_copy;
}

EXPORT_SYMBOL(congdb_get_entry);
