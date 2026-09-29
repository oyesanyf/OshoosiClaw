#ifndef OSOOSI_EBPF_TYPES_H
#define OSOOSI_EBPF_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

// Event Types
#define OSOOSI_EBPF_EVENT_EXEC      1
#define OSOOSI_EBPF_EVENT_EXIT      2
#define OSOOSI_EBPF_EVENT_LSM_BLOCK 3

// Maximum string lengths
#define OSOOSI_COMM_LEN             16
#define OSOOSI_PATH_LEN             256
#define OSOOSI_ARGS_LEN             512

// Process lifecycle event structure (Exec, Exit, LSM Block)
struct ebpf_process_event {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    char comm[OSOOSI_COMM_LEN];
    char filename[OSOOSI_PATH_LEN];
    char args[OSOOSI_ARGS_LEN];
    uint64_t timestamp_ns;
    uint32_t event_type; // 1=Exec, 2=Exit, 3=LsmBlock
    uint32_t _pad;       // 8-byte alignment padding
};

// Network connection event structure
struct ebpf_network_event {
    uint32_t pid;
    uint16_t family;     // AF_INET (2) or AF_INET6 (10)
    uint16_t dport;      // Big-endian destination port
    uint8_t daddr[16];   // IPv4 (in first 4 bytes) or IPv6 address
    uint16_t sport;      // Source port
    uint16_t _pad1;      // 2-byte alignment padding
    uint32_t _pad2;      // 4-byte alignment padding
    uint64_t timestamp_ns;
};

#endif // OSOOSI_EBPF_TYPES_H
