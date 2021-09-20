/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/** SMP - Simple Management Protocol. */

#include <assert.h>
#include <string.h>

#include "cbor.h"
#include "mgmt/endian.h"
#include "mgmt/mgmt.h"
#include "smp/smp.h"

#include "net/buf.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(smp_mcumgr);

static int
smp_align4(int x)
{
    int rem;

    rem = x % 4;
    if (rem == 0) {
        return x;
    } else {
        return x - rem + 4;
    }
}

/**
 * Converts a request opcode to its corresponding response opcode.
 */
static uint8_t
smp_rsp_op(uint8_t req_op)
{
    if (req_op == MGMT_OP_READ) {
        return MGMT_OP_READ_RSP;
    } else {
        return MGMT_OP_WRITE_RSP;
    }
}

static void
smp_init_rsp_hdr(const struct mgmt_hdr *req_hdr, struct mgmt_hdr *rsp_hdr)
{
    *rsp_hdr = (struct mgmt_hdr) {
        .nh_len = 0,
        .nh_flags = 0,
        .nh_op = smp_rsp_op(req_hdr->nh_op),
        .nh_group = req_hdr->nh_group,
        .nh_seq = req_hdr->nh_seq,
        .nh_id = req_hdr->nh_id,
    };
}

static int
smp_read_hdr(struct smp_streamer *streamer, struct mgmt_hdr *dst_hdr)
{
    if (streamer->mgmt_stmr.reader.nb->size < sizeof *dst_hdr) {
        return MGMT_ERR_EINVAL;
    }

    memcpy((char *)dst_hdr, streamer->mgmt_stmr.reader.nb->data, sizeof *dst_hdr);
    return 0;
}

static int
smp_write_hdr(struct smp_streamer *streamer, const struct mgmt_hdr *src_hdr)
{
    int rc;

    rc = mgmt_streamer_write_at(&streamer->mgmt_stmr, 0, src_hdr,
                                sizeof *src_hdr);
    return mgmt_err_from_cbor(rc);
}

static int
smp_build_err_rsp(struct smp_streamer *streamer,
                  const struct mgmt_hdr *req_hdr,
                  int status)
{
    struct mgmt_ctxt cbuf;
    struct mgmt_hdr rsp_hdr;
    struct buffer_ctxt encBuf;
    struct buffer_ctxt decBuf;
    int rc;

    /* encoding should happen on the payload_encoder and not on the cbuf.encoder
     * so create a copy of cbuf and replace the encoder pointer
     * Nasty but effective hack */
    struct mgmt_ctxt payload_ctxt;

    /* give the netbuffer memory region to the cbor encoder but with an offset where the header is placed */
    encBuf.buffer = streamer->mgmt_stmr.writer.nb->data + MGMT_HDR_SIZE;
    encBuf.size = streamer->mgmt_stmr.writer.nb->size - MGMT_HDR_SIZE;

    decBuf.buffer = streamer->mgmt_stmr.reader.nb->data;
    decBuf.size = streamer->mgmt_stmr.reader.nb->len;/* use the actual nr of encoded bytes in the buffer, not the max size */

    rc = mgmt_ctxt_init(&cbuf, &encBuf, &decBuf);
    if (rc != 0) {
        return rc;
    }

    smp_init_rsp_hdr(req_hdr, &rsp_hdr);
    rc = smp_write_hdr(streamer, &rsp_hdr);
    if (rc != 0) {
        return rc;
    }

    /* deliberate shallow copies */
    payload_ctxt.parser = cbuf.parser;
    payload_ctxt.it = cbuf.it;

    rc = cbor_encoder_create_map(&cbuf.encoder, &payload_ctxt.encoder, CborIndefiniteLength);
    if (rc != 0) {
        return rc;
    }

    rc = mgmt_write_rsp_status(&payload_ctxt, status);
    if (rc != 0) {
        return rc;
    }

    rc = cbor_encoder_close_container(&cbuf.encoder, &payload_ctxt.encoder);
    if (rc != 0) {
        return rc;
    }

    /* Fix up the response header with the correct length. */
    rsp_hdr.nh_len = cbor_encoder_get_buffer_size(&cbuf.encoder, encBuf.buffer);
    /* update the netbuffer length, used in outputting the packet */
    streamer->mgmt_stmr.writer.nb->len += rsp_hdr.nh_len;
    mgmt_hton_hdr(&rsp_hdr);
    rc = smp_write_hdr(streamer, &rsp_hdr);
    if (rc != 0) {
        return rc;
    }

    return 0;
}

/**
 * Processes a single SMP request and generates a response payload (i.e.,
 * everything after the management header).  On success, the response payload
 * is written to the supplied cbuf but not transmitted.  On failure, no error
 * response gets written; the caller is expected to build an error response
 * from the return code.
 *
 * @param cbuf                  A cbuf containing the request and response
 *                                  buffer.
 * @param req_hdr               The management header belonging to the incoming
 *                                  request (host-byte order).
 *
 * @return                      A MGMT_ERR_[...] error code.
 */
static int
smp_handle_single_payload(struct mgmt_ctxt *cbuf,
                          const struct mgmt_hdr *req_hdr, bool *handler_found)
{
    const struct mgmt_handler *handler;
    mgmt_handler_fn *handler_fn;

    /* encoding should happen on the payload_encoder and not on the cbuf.encoder
     * so create a copy of cbuf and replace the encoder pointer
     * Nasty but effective hack */
    struct mgmt_ctxt payload_ctxt;
    /* deliberate shallow copies */
    payload_ctxt.parser = cbuf->parser;
    payload_ctxt.it = cbuf->it;
    int rc;

    handler = mgmt_find_handler(req_hdr->nh_group, req_hdr->nh_id);
    LOG_ERR("smp_handle_single_payload: mgmt_find_handler returned ptr %X", handler);
    if (handler == NULL) {
        LOG_ERR("smp_handle_single_payload: failed to find handler for groupId %d and commandId %d", req_hdr->nh_group, req_hdr->nh_id);
        return MGMT_ERR_ENOTSUP;
    }

    /* Begin response payload.  Response fields are inserted into the root
     * map as key value pairs.
     */
    rc = cbor_encoder_create_map(&cbuf->encoder, &payload_ctxt.encoder,
                                 CborIndefiniteLength);
    LOG_ERR("smp_handle_single_payload: cbor_encoder_create_map %d", rc);
    rc = mgmt_err_from_cbor(rc);
    LOG_ERR("smp_handle_single_payload: mgmt_err_from_cbor %d", rc);
    if (rc != 0) {
        return rc;
    }

    switch (req_hdr->nh_op) {
    case MGMT_OP_READ:
        handler_fn = handler->mh_read;
        break;

    case MGMT_OP_WRITE:
        handler_fn = handler->mh_write;
        break;

    default:
        return MGMT_ERR_EINVAL;
    }

    if (handler_fn) {
        *handler_found = true;
        mgmt_evt(MGMT_EVT_OP_CMD_RECV, req_hdr->nh_group, req_hdr->nh_id, NULL);

        rc = handler_fn(&payload_ctxt);
        LOG_ERR("smp_handle_single_payload: handler_fn %d", rc);
        LOG_ERR("smp_handle_single_payload: after calling handler data ptr is at %X", cbuf->encoder.data.ptr);
    } else {
        LOG_ERR("smp_handle_single_payload: handler_found unset %d", req_hdr->nh_op);
        rc = MGMT_ERR_ENOTSUP;
    }

    if (rc != 0) {
        return rc;
    }

    /* End response payload. */
    rc = cbor_encoder_close_container(&cbuf->encoder, &payload_ctxt.encoder);
    LOG_ERR("smp_handle_single_payload: cbor_encoder_close_container %d", rc);
    LOG_ERR("smp_handle_single_payload: after closing container data ptr is at %X", cbuf->encoder.data.ptr);
    return mgmt_err_from_cbor(rc);
}

/**
 * Processes a single SMP request and generates a complete response (i.e.,
 * header and payload).  On success, the response is written using the supplied
 * streamer but not transmitted.  On failure, no error response gets written;
 * the caller is expected to build an error response from the return code.
 *
 * @param streamer              The SMP streamer to use for reading the request
 *                                  and writing the response.
 * @param req_hdr               The management header belonging to the incoming
 *                                  request (host-byte order).
 *
 * @return                      A MGMT_ERR_[...] error code.
 */
static int
smp_handle_single_req(struct smp_streamer *streamer,
                      const struct mgmt_hdr *req_hdr, bool *handler_found)
{
    struct mgmt_ctxt cbuf;
    struct mgmt_hdr rsp_hdr;
    struct buffer_ctxt encBuf;
    struct buffer_ctxt decBuf;
    int rc;

    /* give the netbuffer memory region to the cbor encoder but with an offset where the header is placed */
    encBuf.buffer = streamer->mgmt_stmr.writer.nb->data + MGMT_HDR_SIZE;
    encBuf.size = streamer->mgmt_stmr.writer.nb->size - MGMT_HDR_SIZE;

    decBuf.buffer = streamer->mgmt_stmr.reader.nb->data;
    decBuf.size = streamer->mgmt_stmr.reader.nb->len;/* use the actual nr of encoded bytes in the buffer, not the max size */

    rc = mgmt_ctxt_init(&cbuf, &encBuf, &decBuf);
    LOG_ERR("smp_handle_single_req: mgmt_ctxt_init %d", rc);
    if (rc != 0) {
        return rc;
    }

    /* Write a dummy header to the beginning of the response buffer.  Some
     * fields will need to be fixed up later.
     */
    smp_init_rsp_hdr(req_hdr, &rsp_hdr);
    LOG_ERR("smp_handle_single_req: writing dummy response header of size %d to %X", sizeof(rsp_hdr), streamer->mgmt_stmr.writer.encoder.data.ptr);
    rc = smp_write_hdr(streamer, &rsp_hdr);
    LOG_ERR("smp_handle_single_req: smp_write_hdr %d", rc);
    if (rc != 0) {
        return rc;
    }

    /* Process the request and write the response payload. */
    LOG_ERR("smp_handle_single_req: writing response data to %X", cbuf.encoder.data.ptr);
    rc = smp_handle_single_payload(&cbuf, req_hdr, handler_found);
    LOG_ERR("smp_handle_single_req: smp_handle_single_payload %d", rc);
    if (rc != 0) {
        return rc;
    }

    LOG_ERR("smp_handle_single_req: after writing response data ptr is at %X, start address %X", cbuf.encoder.data.ptr, encBuf.buffer);
    LOG_ERR("smp_handle_single_req: nr encoded response bytes %d", cbor_encoder_get_buffer_size(&cbuf.encoder, encBuf.buffer));

    /* Fix up the response header with the correct length. */
    rsp_hdr.nh_len = cbor_encoder_get_buffer_size(&cbuf.encoder, encBuf.buffer);
    /* update the netbuffer length, used in outputting the packet */
    streamer->mgmt_stmr.writer.nb->len += rsp_hdr.nh_len;
    mgmt_hton_hdr(&rsp_hdr);
    LOG_ERR("smp_handle_single_req: writing actual response header of size %d to %X", sizeof(rsp_hdr), streamer->mgmt_stmr.writer.encoder.data.ptr);
    rc = smp_write_hdr(streamer, &rsp_hdr);
    LOG_ERR("smp_handle_single_req: smp_write_hdr %d", rc);
    if (rc != 0) {
        return rc;
    }

    return 0;
}

/**
 * Attempts to transmit an SMP error response.  This function consumes both
 * supplied buffers.
 *
 * @param streamer              The SMP streamer for building and transmitting
 *                                  the response.
 * @param req_hdr               The header of the request which elicited the
 *                                  error.
 * @param req                   The buffer holding the request.
 * @param rsp                   The buffer holding the response, or NULL if
 *                                  none was allocated.
 * @param status                The status to indicate in the error response.
 */
static void
smp_on_err(struct smp_streamer *streamer, const struct mgmt_hdr *req_hdr,
           void *req, void *rsp, int status)
{
    int rc;

    /* Prefer the response buffer for holding the error response.  If no
     * response buffer was allocated, use the request buffer instead.
     */
    if (rsp == NULL) {
        rsp = req;
        req = NULL;
    }

    /* Clear the partial response from the buffer, if any. */
    mgmt_streamer_reset_buf(&streamer->mgmt_stmr, rsp);
    mgmt_streamer_init_writer(&streamer->mgmt_stmr, rsp);

    /* Build and transmit the error response. */
    rc = smp_build_err_rsp(streamer, req_hdr, status);
    if (rc == 0) {
        streamer->tx_rsp_cb(streamer, rsp, streamer->mgmt_stmr.cb_arg);
        rsp = NULL;
    }

    /* Free any extra buffers. */
    mgmt_streamer_free_buf(&streamer->mgmt_stmr, req);
    mgmt_streamer_free_buf(&streamer->mgmt_stmr, rsp);
}

/**
 * Processes all SMP requests in an incoming packet.  Requests are processed
 * sequentially from the start of the packet to the end.  Each response is sent
 * individually in its own packet.  If a request elicits an error response,
 * processing of the packet is aborted.  This function consumes the supplied
 * request buffer regardless of the outcome.
 *
 * @param streamer              The streamer to use for reading, writing, and
 *                                  transmitting.
 * @param req                   A buffer containing the request packet.
 *
 * @return                      0 on success, MGMT_ERR_[...] code on failure.
 */
int
smp_process_request_packet(struct smp_streamer *streamer, void *req)
{
    struct mgmt_hdr req_hdr;
    struct mgmt_evt_op_cmd_done_arg cmd_done_arg;
    void *rsp;
    bool valid_hdr, handler_found;
    int rc;

    rsp = NULL;
    valid_hdr = true;

    int loop_cnt = 0;

    while (1) {
        loop_cnt++;
        LOG_ERR("smp_process_request_packet: entered loop cnt %d", loop_cnt);

        handler_found = false;

        rc = mgmt_streamer_init_reader(&streamer->mgmt_stmr, req);
        LOG_ERR("smp_process_request_packet: mgmt_streamer_init_reader %d", rc);
        if (rc != 0) {
            valid_hdr = false;
            break;
        }

        /* Read the management header and strip it from the request. */
        rc = smp_read_hdr(streamer, &req_hdr);
        LOG_ERR("smp_process_request_packet: smp_read_hdr %d from address %X", rc, streamer->mgmt_stmr.reader.nb->data);
        if (rc != 0) {
            valid_hdr = false;
            break;
        }
        mgmt_ntoh_hdr(&req_hdr);

        LOG_ERR("smp_process_request_packet: decoded header into groupId %d and commandId %d", req_hdr.nh_group, req_hdr.nh_id);
        LOG_ERR("smp_process_request_packet: CBorValue iterator ptr at address %X", streamer->mgmt_stmr.reader.it.ptr);
        
        mgmt_streamer_trim_front(&streamer->mgmt_stmr, req, MGMT_HDR_SIZE);

        rsp = mgmt_streamer_alloc_rsp(&streamer->mgmt_stmr, req);
        LOG_ERR("smp_process_request_packet: mgmt_streamer_alloc_rsp ptr %X", rsp);
        if (rsp == NULL) {
            rc = MGMT_ERR_ENOMEM;
            break;
        }

        rc = mgmt_streamer_init_writer(&streamer->mgmt_stmr, rsp);
        LOG_ERR("smp_process_request_packet: mgmt_streamer_init_writer %d", rc);
        if (rc != 0) {
            break;
        }

        LOG_ERR("smp_process_request_packet: set writer ptr to %X", streamer->mgmt_stmr.writer.encoder.data.ptr);

        /* Process the request payload and build the response. */
        rc = smp_handle_single_req(streamer, &req_hdr, &handler_found);
        LOG_ERR("smp_process_request_packet: smp_handle_single_req %d", rc);
        if (rc != 0) {
            break;
        }

        /* Send the response. */
        rc = streamer->tx_rsp_cb(streamer, rsp, streamer->mgmt_stmr.cb_arg);
        LOG_ERR("smp_process_request_packet: tx_rsp_cb %d", rc);
        rsp = NULL;
        if (rc != 0) {
            break;
        }

        /* Trim processed request to free up space for subsequent responses. */
        mgmt_streamer_trim_front(&streamer->mgmt_stmr, req,
                                 smp_align4(req_hdr.nh_len));

        cmd_done_arg.err = MGMT_ERR_EOK;
        mgmt_evt(MGMT_EVT_OP_CMD_DONE, req_hdr.nh_group, req_hdr.nh_id,
                 &cmd_done_arg);
    }

    if (rc != 0 && valid_hdr) {
        smp_on_err(streamer, &req_hdr, req, rsp, rc);

        if (handler_found) {
            cmd_done_arg.err = rc;
            mgmt_evt(MGMT_EVT_OP_CMD_DONE, req_hdr.nh_group, req_hdr.nh_id,
                     &cmd_done_arg);
        }

        return rc;
    }

    mgmt_streamer_free_buf(&streamer->mgmt_stmr, req);
    mgmt_streamer_free_buf(&streamer->mgmt_stmr, rsp);
    return 0;
}
