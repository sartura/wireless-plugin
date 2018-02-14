#include "operational.h"
#include "common.h"

#define MAX_UBUS_PATH 100
#define UBUS_INVOKE_TIMEOUT 200

struct status_container {
    char *interface_name;
    const char *ubus_method;
    ubus_val_to_sr_val transform;
    struct list_head *list;
};

struct ubus_context *ctx;
struct status_container *container_msg;

int
operational_start()
{
    if (ctx) return 0;
    INF("Connect ubus context. %zu", (size_t) ctx);
    container_msg = calloc(1,sizeof(*container_msg));

    ctx = ubus_connect(NULL);
    if (ctx == NULL) {
        INF_MSG("Cant allocate ubus\n");
        return -1;
    }

    return 0;
}

void
operational_stop()
{
    INF_MSG("Free ubus context.");
    INF("%lu %lu", (long unsigned)ctx, (long unsigned) container_msg);
    if (ctx) ubus_free(ctx);
    if (container_msg) free(container_msg);
}

static void
make_status_container(struct status_container **context,
                      const char *ubus_method_to_call,
                      ubus_val_to_sr_val result_function,
                      char *interface_name, struct list_head *list)
{
    *context = container_msg;
    (*context)->interface_name = interface_name;
    (*context)->transform = result_function;
    (*context)->ubus_method = ubus_method_to_call;
    (*context)->list = list;
}

static void
ubus_base_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *json_string;
    struct json_object *base_object;
    struct status_container *status_container_msg;

    status_container_msg = (struct status_container *) req->priv;

    if (!msg) {
        return;
    }

    json_string = blobmsg_format_json(msg, true);
    base_object = json_tokener_parse(json_string);

    status_container_msg->transform(base_object, status_container_msg->interface_name, status_container_msg->list);

    json_object_put(base_object);
    free(json_string);
}

static int
ubus_base(const char *ubus_lookup_path,
          struct status_container *msg, struct blob_buf *blob)
{
    uint32_t id = 0;
    int rc = SR_ERR_OK;

    rc = ubus_lookup_id(ctx, ubus_lookup_path, &id);
    if (rc) {
        goto exit;
    }

    rc = ubus_invoke(ctx, id, "status", blob->head, ubus_base_cb, (void *) msg, UBUS_INVOKE_TIMEOUT);
    if (rc) {
        INF("ubus [%s]: no object %s\n", ubus_strerror(rc), msg->ubus_method);
        goto exit;
    }

  exit:
    blob_buf_free(blob);

    return rc;

}

static void
operstatus_channel_f(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/terastream-wireless:devices-state/device[name='%s']/channel";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base,
                              "channel",
                              &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_ENUM_T, ubus_result);

    list_add(&list_value->head, list);
}

int
operational_channel(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_channel_f, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf, "vif", interface_name);
    ubus_base("router.wireless", msg, &buf);

    return SR_ERR_OK;
}

static void
operstatus_encryption_f(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/terastream-wireless:devices-state/device[name='%s']/encryption";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base,
                              "encryption",
                              &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result) return;

    /* transform ubus_result to acceptable YANG format */
    if (0 == strcmp(ubus_result, "Disabled")) {
        ubus_result = "none";
    } else if (0 == strcmp(ubus_result, "WEP")) {
        ubus_result = "wep-open";
    } else if (0 == strcmp(ubus_result, "WPA2 PSK")) {
        ubus_result = "psk2";
    } else if (0 == strcmp(ubus_result, "WPA\\/WPA2 PSK")) {
        ubus_result = "psk-psk2";
    } else if (0 == strcmp(ubus_result, "WPA2 802.1x")) {
        ubus_result = "wpa2";
    } else if (0 == strcmp(ubus_result, "WPA\\/WPA2 802.1x")) {
        ubus_result = "wpa-wpa2";
    }

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_ENUM_T, ubus_result);

    list_add(&list_value->head, list);
}

int
operational_encryption(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_encryption_f, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf, "vif", interface_name);
    ubus_base("router.wireless", msg, &buf);

    return SR_ERR_OK;
}

static void
operstatus_ssid_f(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/terastream-wireless:devices-state/device[name='%s']/ssid";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base,
                              "ssid",
                              &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_STRING_T, ubus_result);

    list_add(&list_value->head, list);
}

int
operational_ssid(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_ssid_f, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf, "vif", interface_name);
    ubus_base("router.wireless", msg, &buf);

    return SR_ERR_OK;
}


static void
operstatus_up_f(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/terastream-wireless:devices-state/device[name='%s']/up";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base,
                              "up",
                              &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    bool up = strcmp("true", ubus_result) == 0 ? true : false;
    list_value->value->type = SR_BOOL_T;
    list_value->value->data.bool_val = up;

    list_add(&list_value->head, list);
}

int
operational_up(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_up_f, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf, "name", interface_name);
    ubus_base("network.device", msg, &buf);

    return SR_ERR_OK;
}


