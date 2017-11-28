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

void __del_entry(struct congdb_entry *entry)
{
    list_del(&entry->lnode);
    kfree(entry->ca_name);
    kfree(entry);
}

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

EXPORT_SYMBOL(congdb_get_entry);
