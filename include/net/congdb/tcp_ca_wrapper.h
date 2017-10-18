#ifndef CA_WRAPPER_H_
#define CA_WRAPPER_H_
#include <net/tcp.h>


#define IMPORT_SYMBOL_VALUE_FOR_tcp_ca_find_key (0xffffffff817f9e70UL)
#define IMPORT_SYMBOL(name) \
    static typeof(&name) IMPORTED(name) __attribute__((unused)) = (typeof(&name))IMPORT_SYMBOL_VALUE_FOR_ ## name
#define IMPORTED(name) __i__ ## name


IMPORT_SYMBOL(tcp_ca_find_key);
#endif  /* CA_WRAPPER_H_ */
