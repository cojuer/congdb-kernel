#ifndef _CONGDB_MANAGER_H
#define _CONGDB_MANAGER_H

#include <linux/list.h>
#include <net/genetlink.h>

struct tcp_sock_data {
    uint32_t loc_ip;
    uint32_t rem_ip;
};

struct congdb_entry_data {
    struct tcp_sock_data stats;
    char* ca_name;
};

struct congdb_data {
    size_t size;
    struct congdb_entry_data entries[];
};

struct congdb_data* congdb_data_alloc(size_t size);
void congdb_data_free(struct congdb_data *confs);

// operations on database
int congdb_add_entry(struct tcp_sock_data *tcp_data, char* ca);
int congdb_del_entry(struct tcp_sock_data *tcp_data);
void congdb_clear_entries(void);
struct congdb_data* congdb_list_entries(void);

//TEST
const char* congdb_get_entry(uint32_t loc_ip, uint32_t rem_ip);

#endif