/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pty.h>
#include <uwsc/uwsc.h>
#include <libubox/blobmsg_json.h>

#include "utils.h"

#define KEEPALIVE_INTERVAL  30
struct tty_session {
    pid_t pid;
    int pty;
    char sid[33];
    struct ustream_fd sfd;
    struct list_head node;
};

struct uwsc_client *cl;
struct uloop_fd fd;

static char buf[4096];
static struct blob_buf b;
static char mac[128];

LIST_HEAD(tty_sessions);

enum {
    RTTYD_TYPE,
    RTTYD_MAC,
    RTTYD_SID
};

static const struct blobmsg_policy pol[] = {
    [RTTYD_TYPE] = {
        .name = "type",
        .type = BLOBMSG_TYPE_STRING,
    },
    [RTTYD_MAC] = {
        .name = "mac",
        .type = BLOBMSG_TYPE_STRING,
    },
    [RTTYD_SID] = {
        .name = "sid",
        .type = BLOBMSG_TYPE_STRING,
    }
};

static void keepalive(struct uloop_timeout *utm)
{
    char *str;

    blobmsg_buf_init(&b);
    blobmsg_add_string(&b, "type", "ping");
    blobmsg_add_string(&b, "mac", mac);

    str = blobmsg_format_json(b.head, true);

    cl->send(cl, str, strlen(str), WEBSOCKET_OP_TEXT);

    uloop_timeout_set(utm, KEEPALIVE_INTERVAL * 1000);
}

static void pty_read_cb(struct ustream *s, int bytes)
{
    struct tty_session *ts = container_of(s, struct tty_session, sfd.stream);
    char *str;
    int len;

    str = ustream_get_read_buf(s, &len);
    
    blobmsg_buf_init(&b);
    blobmsg_add_string(&b, "type", "data");
    blobmsg_add_string(&b, "mac", mac);
    blobmsg_add_string(&b, "sid", ts->sid);

    b64_encode(str, len, buf, sizeof(buf));
    blobmsg_add_string(&b, "data", buf);

    str = blobmsg_format_json(b.head, true);

    cl->send(cl, str, strlen(str), WEBSOCKET_OP_TEXT);
}

static void new_tty_session(struct blob_attr **tb)
{
    struct tty_session *s;
    int pty;
    pid_t pid;
    struct blob_attr *cur;

    cur = tb[RTTYD_MAC]; 
    if (!cur)
        return;

    cur = tb[RTTYD_SID];
    if (!cur)
        return;

    s = calloc(1, sizeof(struct tty_session));
    if (!s)
        return;

    pid = forkpty(&pty, NULL, NULL, NULL);
    if (pid == 0)
        execl("/bin/login", "/bin/login", NULL);

    s->pid = pid;
    s->pty = pty;
    memcpy(s->sid, blobmsg_get_string(tb[RTTYD_SID]), 32);
    
    list_add(&s->node, &tty_sessions);

    s->sfd.stream.notify_read = pty_read_cb;
    ustream_fd_init(&s->sfd, s->pty);
}

void fd_handler(struct uloop_fd *u, unsigned int events)
{
    char buf[128] = "";
    int n;

    n = read(u->fd, buf, sizeof(buf));
    if (n > 1) {
        buf[n - 1] = 0;
        printf("You input:[%s]\n", buf);
        cl->send(cl, buf, strlen(buf), WEBSOCKET_OP_TEXT);
    }
}

static void uwsc_onopen(struct uwsc_client *cl)
{
    uwsc_log_debug("onopen");

    fd.fd = STDIN_FILENO;
    fd.cb = fd_handler;
    uloop_fd_add(&fd, ULOOP_READ);
}

static void uwsc_onmessage(struct uwsc_client *cl, char *data, uint64_t len, enum websocket_op op)
{
    struct blob_attr *tb[ARRAY_SIZE(pol)];
    const char *type;

    blobmsg_buf_init(&b);

    blobmsg_add_json_from_string(&b, data);

    if (blobmsg_parse(pol, ARRAY_SIZE(pol), tb, blob_data(b.head), blob_len(b.head)) != 0) {
        fprintf(stderr, "Parse failed\n");
        return;
    }

    if (!tb[RTTYD_TYPE])
        return;

    type = blobmsg_get_string(tb[RTTYD_TYPE]);
    if (!strcmp(type, "login"))
        new_tty_session(tb);
}

static void uwsc_onerror(struct uwsc_client *cl)
{
    printf("onerror:%d\n", cl->error);
}

static void uwsc_onclose(struct uwsc_client *cl)
{
    printf("onclose\n");

    uloop_done();
}

int main(int argc, char **argv)
{
    struct uloop_timeout keepalive_timer = {
        .cb = keepalive
    };

    uloop_init();

    get_iface_mac("ens38", mac, sizeof(mac));

    cl = uwsc_new("ws://127.0.0.1:81/lua");
   
    cl->onopen = uwsc_onopen;
    cl->onmessage = uwsc_onmessage;
    cl->onerror = uwsc_onerror;
    cl->onclose = uwsc_onclose;
    
    keepalive(&keepalive_timer);

    uloop_run();
    uloop_done();
    
    cl->free(cl);

    return 0;
}
