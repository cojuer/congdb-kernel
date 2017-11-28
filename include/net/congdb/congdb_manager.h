#ifndef _CONGDB_MANAGER_H
#define _CONGDB_MANAGER_H

#include <linux/list.h>
#include <net/genetlink.h>

struct rule_id {
    uint32_t loc_ip;
    uint32_t loc_mask;
    uint32_t rem_ip;
    uint32_t rem_mask;
    uint8_t  priority;
};

struct rule_stats {
    uint32_t acks_num;
    uint32_t loss_num;
    uint32_t rtt;
};

struct congdb_entry_data {
    struct rule_id id;
    struct rule_stats stats;
    char* ca_name;
};

struct congdb_data {
    size_t size;
    struct congdb_entry_data entries[];
};

struct congdb_data* congdb_data_alloc(size_t size);
void congdb_data_free(struct congdb_data *confs);

// operations on database
int congdb_add_entry(struct rule_id *id, char* ca);
int congdb_del_entry(struct rule_id *id);
void congdb_clear_entries(void);
struct congdb_data* congdb_list_entries(void);

//TEST
const char* congdb_get_entry(uint32_t loc_ip, uint32_t rem_ip);
void congdb_aggregate_stats(uint32_t loc_ip, uint32_t rem_ip, void *stats);

#endif