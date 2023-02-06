// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include "rados/librados.h"
#include "rbd/librbd.h"

#include "ublksrv_tgt.h"

#define RBD_MAX_NAME	512

#define RBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, name, val) do {         \
	int ret;                                                        \
	if (val)                                                        \
            ret = ublksrv_json_write_target_str_info(jbuf,              \
                                                     jbuf_size, name, val); \
	else                                                            \
            ret = 0;                                                    \
	if (ret < 0)                                                    \
            jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);	\
	else                                                            \
            break;                                                      \
    } while (1)

#define RBD_WRITE_TGT_LONG(dev, jbuf, jbuf_size, name, val) do {        \
	int ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size, \
                                                       name, val);      \
	if (ret < 0)							\
            jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);	\
	else                                                            \
            break;                                                      \
    } while (1)

struct rbd_completion_ctx {
    const struct ublksrv_queue *q;
    const struct ublk_io_data *data;
    int tag;

    rbd_completion_ctx(const struct ublksrv_queue *q,
                       const struct ublk_io_data *data, int tag)
        : q(q), data(data), tag(tag) {
    }
};

struct rbd_state {
    rados_t rados;
    rados_ioctx_t ioctx;
    rbd_image_t image;
};

static inline rbd_state *dev_to_rbd_state(const struct ublksrv_dev *dev)
{
    return (rbd_state *)dev->tgt.tgt_data;
}

static inline rbd_state *queue_to_rbd_state(const struct ublksrv_queue *q)
{
    return (rbd_state *)q->private_data;
}

static int rbd_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery)
{
    struct ublksrv_tgt_info *tgt = &dev->tgt;
    const struct ublksrv_ctrl_dev_info *info =
        ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    int jbuf_size;
    char *jbuf = ublksrv_tgt_return_json_buf(dev, &jbuf_size);
    int i;

    char pool_name[RBD_MAX_NAME] = {0};
    char namespace_name[RBD_MAX_NAME] = {0};
    char image_name[RBD_MAX_NAME] = {0};
    char snapshot_name[RBD_MAX_NAME] = {0};
    long read_only = 0;
    int ret;
        
    ublk_assert(jbuf);
    ublk_assert(type == UBLKSRV_TGT_TYPE_RBD);
    ublk_assert(!recovery || info->state == UBLK_S_DEV_QUIESCED);

    ublksrv_json_read_target_str_info(jbuf, RBD_MAX_NAME, "pool",
                                      pool_name);
    ublksrv_json_read_target_str_info(jbuf, RBD_MAX_NAME, "namespace",
                                      namespace_name);
    ublksrv_json_read_target_str_info(jbuf, RBD_MAX_NAME, "image",
                                      image_name);
    ublksrv_json_read_target_str_info(jbuf, RBD_MAX_NAME, "snapshot",
                                      snapshot_name);
    ublksrv_json_read_target_ulong_info(jbuf, "read_only", &read_only);

    ublksrv_log(LOG_INFO,
                "%s: pool %s namespace %s image %s snapshot %s read_only %l\n",
                __func__, pool_name, namespace_name, image_name,
                snapshot_name, read_only);

    rbd_state *rs = new rbd_state();

    ret = rados_create(&rs->rados, NULL);
    if (ret < 0) {
        syslog(LOG_ERR, "%s: failed to init rados: %d\n", __func__, ret);
        goto fail;
    }
    ret = rados_conf_read_file(rs->rados, NULL);
    if (ret < 0) {
        syslog(LOG_ERR, "%s: failed to read config: %d\n", __func__, ret);
        goto fail;
    }

    rados_conf_parse_env(rs->rados, NULL);

    ret = rados_connect(rs->rados);
    if (ret < 0) {
        syslog(LOG_ERR, "%s: failed to connect to cluster: %d\n", __func__,
               ret);
        goto fail;
    }

    ret = rados_ioctx_create(rs->rados, pool_name, &rs->ioctx);
    if (ret < 0) {
        syslog(LOG_ERR, "%s: failed to access pool %s: %d\n", __func__,
               pool_name, ret);
        goto shutdown_rados;
    }

    rados_ioctx_set_namespace(rs->ioctx, namespace_name);

    ret = rbd_open(rs->ioctx, image_name, &rs->image, snapshot_name);
    if (ret) {
        syslog(LOG_ERR, "%s: failed to open image %s: %d\n", __func__,
               image_name, ret);
        goto destroy_ioctx;
    }

    rbd_image_info_t image_info;
    ret = rbd_stat(rs->image, &image_info, sizeof(image_info));
    if (ret) {
        syslog(LOG_ERR, "%s: failed to get image %s info: %d\n", __func__,
               image_name, ret);
        goto close_image;
    }

    tgt->dev_size = image_info.size;
    tgt->tgt_ring_depth = info->queue_depth;
    tgt->nr_fds = info->nr_hw_queues;
    tgt->tgt_data = rs;

    ublksrv_dev_set_cq_depth(dev, 2 * tgt->tgt_ring_depth);

    return 0;

close_image:
    rbd_close(rs->image);
destroy_ioctx:
    rados_ioctx_destroy(rs->ioctx);
shutdown_rados:
    rados_shutdown(rs->rados);
fail:
    delete rs;
    return ret;
}

static int rbd_recovery_tgt(struct ublksrv_dev *dev, int type)
{
    return rbd_setup_tgt(dev, type, true);
}

static int rbd_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
                        *argv[])
{
    int read_only = 0;
    struct ublksrv_tgt_info *tgt = &dev->tgt;
    const struct ublksrv_ctrl_dev_info *info =
        ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    static const struct option rbd_longopts[] = {
        { "pool",      1,       NULL, 0 },
        { "namespace", 1,       NULL, 0 },
        { "image",     1,       NULL, 0 },
        { "snapshot",  1,       NULL, 0 },
        { "read_only", 0, &read_only, 1 },
        { NULL }
    };
    int option_index = 0;
    const char *pool_name = NULL;
    const char *namespace_name = NULL;
    const char *image_name = NULL;
    const char *snapshot_name = NULL;
    int opt;
    int jbuf_size, ret;
    char *jbuf;
    struct ublksrv_tgt_base_json tgt_json = {
        .type = type,
    };

    strcpy(tgt_json.name, "rbd");

    if (type != UBLKSRV_TGT_TYPE_RBD)
        return -1;

    while ((opt = getopt_long(argc, argv, "",
                              rbd_longopts, &option_index)) != -1) {
        if (opt < 0)
            break;
        if (opt > 0)
            continue;

        if (!strcmp(rbd_longopts[option_index].name, "pool"))
            pool_name = optarg;
        if (!strcmp(rbd_longopts[option_index].name, "namespace"))
            namespace_name = optarg;
        if (!strcmp(rbd_longopts[option_index].name, "image"))
            image_name = optarg;
        if (!strcmp(rbd_longopts[option_index].name, "snapshot"))
            snapshot_name = optarg;
    }

    if (!pool_name || !image_name)
        return -1;

    if (snapshot_name) {
        read_only = 1;
    }

    ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, jbuf_size);
    RBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "pool", pool_name);
    RBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "namespace", namespace_name);
    RBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "image_name", image_name);
    RBD_WRITE_TGT_STR(dev, jbuf, jbuf_size, "snapshot", snapshot_name);
    RBD_WRITE_TGT_LONG(dev, jbuf, jbuf_size, "read_only", read_only);

    ret = rbd_setup_tgt(dev, type, false);
    if (ret < 0) {
        return ret;
    }

    tgt_json.dev_size = tgt->dev_size;
    ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);

    struct ublk_params p = {
        .types = UBLK_PARAM_TYPE_BASIC,
        .basic = {
            .attrs = read_only ? UBLK_ATTR_READ_ONLY : 0U,
            .logical_bs_shift	= 9,
            .physical_bs_shift	= 12,
            .io_opt_shift		= 12,
            .io_min_shift		= 9,
            .max_sectors		= info->max_io_buf_bytes >> 9,
            .dev_sectors		= tgt->dev_size >> 9,
        },

        .discard = {
            .max_discard_sectors	= UINT_MAX >> 9,
            .max_discard_segments	= 1,
        },
    };

    do {
        ret = ublksrv_json_write_params(&p, jbuf, jbuf_size);
        if (ret < 0)
            jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
    } while (ret < 0);

    return 0;
}

static void rbd_usage_for_add(void)
{
    printf("           rbd: --pool=$POOL [--namespace=$NAMESPACE] --image=$IMAGE \\\n");
    printf("                [--snapshot=$SNAPSHOT] [--read_only]\n");
}

static void rbd_complete_io(rbd_completion_t c, void *arg)
{
    rbd_completion_ctx *ctx = (rbd_completion_ctx *)arg;

    ublksrv_complete_io(ctx->q, ctx->tag, ctx->data->iod->nr_sectors << 9);

    delete ctx;
    rbd_aio_release(c);
}

static int rbd_handle_io_async(const struct ublksrv_queue *q,
                               const struct ublk_io_data *data)
{
    const struct ublksrv_io_desc *iod = data->iod;
    struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
    unsigned ublk_op = ublksrv_get_op(iod);
    struct rbd_state *rs = queue_to_rbd_state(q);
    struct rbd_completion_ctx *ctx;
    rbd_completion_t c;

    if (!sqe)
        return 0;

    ctx = new rbd_completion_ctx(q, data, data->tag);
    rbd_aio_create_completion(ctx, (rbd_callback_t)rbd_complete_io, &c);

    switch (ublk_op) {
    case UBLK_IO_OP_FLUSH:
        rbd_aio_flush(rs->image, c);
        break;
    case UBLK_IO_OP_WRITE_ZEROES:
    case UBLK_IO_OP_DISCARD:
        rbd_aio_discard(rs->image, iod->start_sector << 9, iod->nr_sectors << 9, c);
        break;
    case UBLK_IO_OP_READ:
        rbd_aio_read(rs->image, iod->start_sector << 9, iod->nr_sectors << 9,
                     (char *)iod->addr, c);
        break;
    case UBLK_IO_OP_WRITE:
        rbd_aio_write(rs->image, iod->start_sector << 9, iod->nr_sectors << 9,
                      (char *)iod->addr, c);
        break;
    default:
        rbd_aio_release(c);
        return -EINVAL;
    }

    ublksrv_log(LOG_DEBUG, "%s: tag %d ublk io %x %x %llx %u\n", __func__,
                data->tag, ublk_op, iod->op_flags, iod->start_sector,
                iod->nr_sectors << 9);
    return 0;
}

static void rbd_deinit_tgt(const struct ublksrv_dev *dev)
{
    rbd_state *rs = dev_to_rbd_state(dev);

    rbd_close(rs->image);
    rados_ioctx_destroy(rs->ioctx);
    rados_shutdown(rs->rados);

    delete rs;
}

struct ublksrv_tgt_type  rbd_tgt_type = {
    .handle_io_async = rbd_handle_io_async,
    .usage_for_add	=  rbd_usage_for_add,
    .init_tgt = rbd_init_tgt,
    .deinit_tgt	=  rbd_deinit_tgt,
    .type	= UBLKSRV_TGT_TYPE_RBD,
    .name	=  "rbd",
    .recovery_tgt = rbd_recovery_tgt,
};

static void tgt_rbd_init() __attribute__((constructor));

static void tgt_rbd_init(void)
{
    ublksrv_register_tgt_type(&rbd_tgt_type);
}
