#ifndef EXCHANGE_TYPES_H
#define EXCHANGE_TYPES_H

#define MSG_TYPES(X) \
    /* Error: This header should never be considered a match, even with itself \
    */ \
    X(exchange_error) \
    /* Purposely induced error */ \
    X(exchange_fake_error) \
    /* Initialization phase: nodes connecting to each other send their ID */ \
    X(exchange_init) \
    /* Cross-check: Leader asynchronously sends this message right before it \
       starts waiting for/receiving buffers from followers */ \
    X(exchange_cross_check_leader_waiting) \
    /* Cross-check: Followers prefix their cross-check buffers with this */ \
    X(exchange_cross_check_follower_buffer) \
    /* Replication: Leader prefixes replication information buffers with this \
       header */ \
    X(exchange_replication_leader) \
    /* Replication: Follower asynchronously sends this message right before it \
       sarts waiting for a exchange_replication_leader message */ \
    X(exchange_replication_follower_waiting) \
    /* About to create a checkpoint */ \
    X(exchange_checkpoint_create) \
    /* Process about to fork */ \
    X(exchange_fork) \
    /* Execution is about to terminate */ \
    X(exchange_terminate)

#define ENUM_LIST(X) X,
typedef enum {
    MSG_TYPES(ENUM_LIST)
    n_msg_types
} msg_type_t;
#undef ENUM_LIST

#define STR_DEF(X) extern const char __ ## X ## _strrep[];
MSG_TYPES(STR_DEF)
#undef STR_DEF

#define STR_DEF_LIST(X) __ ## X ## _strrep,
extern const char *msg_type_strrep[];
#undef STR_DEF_LIST

const char *msg_type_str(msg_type_t msg);

#endif