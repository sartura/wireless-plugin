#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "wireless.h"
#include "operational.h"
#include "common.h"

const char *YANG_MODEL = "wireless";

/* Configuration part of the plugin. */
typedef struct sr_uci_mapping {
    char *default_value;
    sr_type_t default_value_type;
    char *ucipath;
    char *xpath;
} sr_uci_link;

struct wireless_device {
    char *name;
    char *option;
};

struct wireless_interface {
    int32_t index;
    char *option;
};

const char *index_fmt = "/wireless:devices/device[name='%s']/interface[ssid='%s']/index";

static sr_uci_link table_wireless[] = {
    /* wireless */
    { 0, SR_STRING_T, "wireless.%s.type", "/wireless:devices/device[name='%s']/type"},
    { 0, SR_STRING_T, "wireless.%s.country", "/wireless:devices/device[name='%s']/country"},
    { 0, SR_STRING_T, "wireless.%s.band", "/wireless:devices/device[name='%s']/band"},
    { 0, SR_INT32_T, "wireless.%s.bandwidth", "/wireless:devices/device[name='%s']/bandwidth"},
    { 0, SR_INT32_T, "wireless.%s.scantimer", "/wireless:devices/device[name='%s']/scantimer"},
    { 0, SR_INT32_T, "wireless.%s.wmm", "/wireless:devices/device[name='%s']/wmm"},
    { 0, SR_INT32_T, "wireless.%s.wmm_noack",  "/wireless:devices/device[name='%s']/wmm_noack"},
    { 0, SR_INT32_T, "wireless.%s.wmm_apsd","/wireless:devices/device[name='%s']/type" },
    { 0, SR_INT32_T, "wireless.%s.txpower", "/wireless:devices/device[name='%s']/txpower"},
    { 0, SR_STRING_T, "wireless.%s.rateset", "/wireless:devices/device[name='%s']/rateset"},
    { 0, SR_INT32_T, "wireless.%s.frag", "/wireless:devices/device[name='%s']/frag"},
    { 0, SR_INT32_T, "wireless.%s.rts", "/wireless:devices/device[name='%s']/rts"},
    { 0, SR_INT32_T, "wireless.%s.dtim_period", "/wireless:devices/device[name='%s']/dtim_period"},
    { 0, SR_INT32_T, "wireless.%s.beacon_int", "/wireless:devices/device[name='%s']/beacon_int"},
    { 0, SR_INT32_T, "wireless.%s.rxchainps", "/wireless:devices/device[name='%s']/rxchainps"},
    { 0, SR_INT32_T, "wireless.%s.rxchainps_qt", "/wireless:devices/device[name='%s']/rxchainps_qt"},
    { 0, SR_INT32_T, "wireless.%s.rxchainps_pps", "/wireless:devices/device[name='%s']/rxchainps_pps"},
    { 0, SR_INT32_T, "wireless.%s.rifs", "/wireless:devices/device[name='%s']/rifs"},
    { 0, SR_INT32_T, "wireless.%s.rifs_advert", "/wireless:devices/device[name='%s']/rifs_advert"},
    { 0, SR_INT32_T, "wireless.%s.maxassoc", "/wireless:devices/device[name='%s']/maxassoc"},
    { 0, SR_INT32_T, "wireless.%s.beamforming", "/wireless:devices/device[name='%s']/beamforming"},
    { 0, SR_INT32_T, "wireless.%s.doth", "/wireless:devices/device[name='%s']/doth"},
    { 0, SR_INT32_T, "wireless.%s.dfsc", "/wireless:devices/device[name='%s']/dfsc"},
    { 0, SR_STRING_T, "wireless.%s.channel", "/wireless:devices/device[name='%s']/channel"},
    { 0, SR_INT32_T, "wireless.%s.disabled", "/wireless:devices/device[name='%s']/disabled"},
    { 0, SR_STRING_T, "wireless.%s.hwmode", "/wireless:devices/device[name='%s']/hwmode"},

    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].ssid",
      "/wireless:devices/device[name='%s']/interface[ssid='%s']/ssid"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].device",
      "/wireless:devices/device[name='%s']/interface[ssid='%s']/device"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].network", "/wireless:devices/device[name='%s']/interface[ssid='%s']/network"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].mode", "/wireless:devices/device[name='%s']/interface[ssid='%s']/mode"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].encryption", "/wireless:devices/device[name='%s']/interface[ssid='%s']/encryption"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].cipher", "/wireless:devices/device[name='%s']/interface[ssid='%s']/cipher"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].key", "/wireless:devices/device[name='%s']/interface[ssid='%s']/key"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].gtk_rekey", "/wireless:devices/device[name='%s']/interface[ssid='%s']/gtk_rekey"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].macfilter", "/wireless:devices/device[name='%s']/interface[ssid='%s']/macfilter"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].wps_pbc", "/wireless:devices/device[name='%s']/interface[ssid='%s']/wps_pbc"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].wmf_bss_enable", "/wireless:devices/device[name='%s']/interface[ssid='%s']/wmf_bss_enable"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].bss_max" , "/wireless:devices/device[name='%s']/interface[ssid='%s']/bss_max"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].ifname", "/wireless:devices/device[name='%s']/interface[ssid='%s']/ifname"},

};

static oper_mapping table_operational[] = {
    { "channel", operational_channel },
    { "ssid", operational_ssid },
    { "encryption", operational_encryption },
};

/* Update UCI configuration given ucipath and some string value. */
static int set_uci_item(struct uci_context *uctx, char *ucipath, char *value);

/* Get value from UCI configuration given ucipath and result holder. */
static int get_uci_item(struct uci_context *uctx, char *ucipath, char **value);

static bool
val_has_data(sr_type_t type) {
    /* types containing some data */
    switch(type) {
    case SR_BINARY_T:
    case SR_BITS_T:
    case SR_BOOL_T:
    case SR_DECIMAL64_T:
    case SR_ENUM_T:
    case SR_IDENTITYREF_T:
    case SR_INSTANCEID_T:
    case SR_INT8_T:
    case SR_INT16_T:
    case SR_INT32_T:
    case SR_INT64_T:
    case SR_STRING_T:
    case SR_UINT8_T:
    case SR_UINT16_T:
    case SR_UINT32_T:
    case SR_UINT64_T:
    case SR_ANYXML_T:
    case SR_ANYDATA_T:
        return true;
    default: return false;
    }
}

static char *
get_key_value(char *orig_xpath, int n)
{
    char *key = NULL, *node = NULL, *xpath = NULL, *val = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};

    xpath = strdup(orig_xpath);
    node = sr_xpath_next_node(xpath, &state);
    if (NULL == node) {
        goto error;
    }
    int counter = 0;
    while(true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            val = sr_xpath_next_key_value(NULL, &state);
            if (counter++ == n) break;
            /* break; */
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

  error:
    if (NULL != xpath) {
        free(xpath);
    }
    return key ? strdup(val) : NULL;
}

static int
get_uci_item(struct uci_context *uctx, char *ucipath, char **value)
{
    int rc = UCI_OK;
    char path[MAX_UCI_PATH];
    struct uci_ptr ptr;

    sprintf(path, "%s", ucipath);
    rc = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, path);

    if (ptr.o == NULL) {
        return UCI_ERR_NOTFOUND;
    }

    strcpy(*value, ptr.o->v.string);

  exit:
    return rc;
}

static int
set_uci_item(struct uci_context *uctx, char *ucipath, char *value)
{
    int rc = UCI_OK;
    struct uci_ptr ptr;
    char *set_path = calloc(1, MAX_UCI_PATH);

    sprintf(set_path, "%s%s%s", ucipath, "=", value);

    rc = uci_lookup_ptr(uctx, &ptr, set_path, true);
    UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, set_path);

    rc = uci_set(uctx, &ptr);
    UCI_CHECK_RET(rc, exit, "uci_set %d %s", rc, set_path);

    rc = uci_save(uctx, ptr.p);
    UCI_CHECK_RET(rc, exit, "uci_save %d %s", rc, set_path);

    rc = uci_commit(uctx, &(ptr.p), false);
    UCI_CHECK_RET(rc, exit, "uci_commit %d %s", rc, set_path);

  exit:
    free(set_path);

    return rc;
}

#define WIRELESS_DEVICE_NAME_LENGTH 20

static int
wireless_xpath_to_device(char *orig_xpath, struct wireless_device *dev) {
    char *key = NULL, *node = NULL, *xpath = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};

    xpath = strdup(orig_xpath);

    node = sr_xpath_next_node(xpath, &state);
    if (NULL == node) {
        goto error;
    }

    while(true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            key = sr_xpath_next_key_value(NULL, &state);
            dev->name = strdup(key);
            break;
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

    sr_xpath_recover(&state);
    dev->option = sr_xpath_last_node(xpath, &state);

    return SR_ERR_OK;

  error:
    if (NULL != xpath) {
        free(xpath);
    }
    return -1;
}

static int
wireless_xpath_to_interface(sr_session_ctx_t *session, char *xpath, struct wireless_interface *interface) {
    char *name_key = NULL, *ssid_key = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};

    name_key = get_key_value(xpath, 0);
    ssid_key = get_key_value(xpath, 1);

    char index_xpath[XPATH_MAX_LEN];
    sprintf(index_xpath, index_fmt, name_key, ssid_key);

    sr_val_t *value = NULL;
    int rc = sr_get_item(session, index_xpath, &value);
    if (rc) {
        goto error;
    }

    interface->index = value->data.int32_val;

    interface->option = sr_xpath_last_node(xpath, &state);
    sr_xpath_recover(&state);

    return SR_ERR_OK;

  error:
    return -1;
}

static int
sysrepo_to_uci(sr_session_ctx_t  *session, struct uci_context *uctx, sr_val_t *new_val)
{
    char ucipath[MAX_UCI_PATH];
    char *mem = NULL;
    int rc = SR_ERR_OK;

    if (false == val_has_data(new_val->type)) {
        return SR_ERR_OK;
    }

    if (strstr(new_val->xpath, "interface")) {
        /* handle interface  */
        struct wireless_interface interface = { 0, };
        rc = wireless_xpath_to_interface(session, new_val->xpath, &interface);
        if (rc < 0) {
            rc = SR_ERR_INTERNAL;
            goto error;
        }
        snprintf(ucipath, XPATH_MAX_LEN, "wireless.@wifi-iface[%d].%s", interface.index, interface.option);
        mem = sr_val_to_str(new_val);
        rc = set_uci_item(uctx, ucipath, mem);
        UCI_CHECK_RET(rc, uci_error, "get_uci_item %s", sr_strerror(rc));
        if(mem) free(mem);

        goto exit;
    }

    if (strstr(new_val->xpath, "device")) {
        /* handle device  */
        struct wireless_device dev = { 0, 0, };
        rc = wireless_xpath_to_device(new_val->xpath, &dev);
        if (rc < 0) {
            rc = SR_ERR_INTERNAL;
            goto error;
        }
        snprintf(ucipath, XPATH_MAX_LEN, "wireless.%s.%s", dev.name, dev.option);
        mem = sr_val_to_str(new_val);
        rc = set_uci_item(uctx, ucipath, mem);
        UCI_CHECK_RET(rc, uci_error, "get_uci_item %s", sr_strerror(rc));
        if(mem) free(mem);

        goto exit;
    }

  exit:
    return SR_ERR_OK;
  error:
    return rc;
  uci_error:
    return SR_ERR_INTERNAL;
}

static int
wireless_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct plugin_ctx *pctx = (struct plugin_ctx*) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char change_path[XPATH_MAX_LEN] = {0,};

    if (SR_EV_APPLY == event) {
        rc = sr_copy_config(pctx->startup_session, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
        INF("\n\n ========== CONFIG HAS CHANGED: %s ==========\n\n", module_name);
    }

    snprintf(change_path, XPATH_MAX_LEN, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, change_path , &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", change_path);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
                                                 &oper, &old_value, &new_value))) {
        if (SR_OP_CREATED == oper || SR_OP_MODIFIED == oper) {
            rc = sysrepo_to_uci(session, pctx->uctx, new_value);
            sr_print_val(new_value);
        }

        sr_free_val(old_value);
        sr_free_val(new_value);
    }
    INF_MSG("\n\n ========== END OF CHANGES =======================================\n\n");

    pid_t pid = fork();
    if (pid==0) {
        execl("/etc/init.d/network", "network", "restart", (char *) NULL);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

  cleanup:
    sr_free_change_iter(it);

    return SR_ERR_OK;
}

static int
init_sysrepo_data(struct plugin_ctx *pctx, sr_session_ctx_t *session)
{
    const char uci_package_name[] = "wireless";
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    char xpath[XPATH_MAX_LEN];
    char ucipath[MAX_UCI_PATH];
    int rc = SR_ERR_OK;

    rc = uci_load(pctx->uctx, uci_package_name, &package);
    UCI_CHECK_RET(rc, exit, "[%d] Could not load package %s.", rc, uci_package_name);

    int interface_index = 0;

    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        /* INF("uci name type %s %s", name, type); */

        if (strcmp("wifi-device", type) == 0) {
            for (size_t i = 0; i < ARR_SIZE(table_wireless); i++) {
                char *uci_val = calloc(1, 100);

                if (strstr(table_wireless[i].ucipath, "@wifi-iface")) {
                    continue;
                }

                snprintf(xpath, XPATH_MAX_LEN, table_wireless[i].xpath, name);
                snprintf(ucipath, MAX_UCI_PATH, table_wireless[i].ucipath, name);
                rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
                if (UCI_ERR_NOTFOUND == rc) {
                    continue;
                }
                SR_CHECK_RET(rc, exit, "uci getitem: %s %s", ucipath, sr_strerror(rc));
                /* INF("Setting device %s to %s", xpath, uci_val); */
                rc = sr_set_item_str(session, xpath, uci_val, SR_EDIT_DEFAULT);
                SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);
                free(uci_val);

                char *ssid = calloc(1,100);

                for (size_t j = 0; j < ARR_SIZE(table_wireless); j++) {
                    char *uci_val = calloc(1, 100);

                    /* INF("[%s][%d] Setting interface %s %s", name, interface_index, */
                    /*     table_wireless[j].ucipath, table_wireless[j].xpath) */
                    if (!strstr(table_wireless[j].ucipath, "@wifi-iface")) {
                        continue;
                    }

                    snprintf(ucipath, MAX_UCI_PATH, table_wireless[j].ucipath, interface_index);
                    rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
                    if (UCI_ERR_NOTFOUND == rc) {
                        continue;
                    }
                    if (strstr(ucipath, "ssid") != NULL) {
                        ssid = strdup(uci_val);
                        strcpy(ssid, uci_val);
                        continue;

                    }
                    /* INF("\titem found %s with ssid %s", uci_val, ssid); */

                    if (NULL == ssid) {
                        continue;
                    }
                    snprintf(xpath, XPATH_MAX_LEN, table_wireless[j].xpath, name, ssid);
                    /* INF("Setting interface %s to %s", xpath, uci_val); */
                    rc = sr_set_item_str(session, xpath, uci_val, SR_EDIT_DEFAULT);
                    SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);

                    snprintf(xpath, XPATH_MAX_LEN, index_fmt, name, ssid);
                    sr_val_t *value = NULL;
                    sr_new_val(xpath, &value);
                    value->type = SR_INT32_T;
                    value->data.int32_val = interface_index;
                    rc = sr_set_item(session, xpath, value, SR_EDIT_DEFAULT);
                    SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);

                    free(uci_val);
                }


                free(ssid);
            }
            interface_index = interface_index + 1;
        }
    }


    rc = sr_commit(session);
    SR_CHECK_RET(rc, exit, "Couldn't commit initial interfaces: %s", sr_strerror(rc));

  exit:
    if (package) uci_unload(pctx->uctx, package);
    return rc;
}

int sync_datastores(struct plugin_ctx *ctx)
{
    char startup_file[XPATH_MAX_LEN] = {0};
    int rc = SR_ERR_OK;
    struct stat st;

    /* check if the startup datastore is empty
     * by checking the content of the file */
    snprintf(startup_file, XPATH_MAX_LEN, "/etc/sysrepo/data/%s.startup", YANG_MODEL);

    if (stat(startup_file, &st) != 0) {
        ERR("Could not open sysrepo file %s", startup_file);
        return SR_ERR_INTERNAL;
    }

    if (0 == st.st_size) {
        /* parse uci config */
        rc = init_sysrepo_data(ctx, ctx->startup_session);
        /* rc = init_sysrepo_data(ctx); */
        INF_MSG("copy uci data to sysrepo");
        SR_CHECK_RET(rc, error, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));

    }else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        SR_CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));

    }

  error:
    return rc;
}

static size_t
list_size(struct list_head *list)
{
    size_t current_size = 0;
    struct value_node *vn;

    list_for_each_entry(vn, list, head) {
        current_size += 1;
    }

    return current_size;
}

int
sr_dup_val_data(sr_val_t *dest, const sr_val_t *source)
{
    int rc = SR_ERR_OK;

    switch (source->type) {
    case SR_BINARY_T:
        rc = sr_val_set_str_data(dest, source->type, source->data.binary_val);
        break;
    case SR_BITS_T:
        rc = sr_val_set_str_data(dest, source->type, source->data.bits_val);
        break;
    case SR_ENUM_T:
        rc = sr_val_set_str_data(dest, source->type, source->data.enum_val);
        break;
    case SR_IDENTITYREF_T:
        rc = sr_val_set_str_data(dest, source->type, source->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        rc = sr_val_set_str_data(dest, source->type, source->data.instanceid_val);
        break;
    case SR_STRING_T:
        rc = sr_val_set_str_data(dest, source->type, source->data.string_val);
        break;
    case SR_BOOL_T:
    case SR_DECIMAL64_T:
    case SR_INT8_T:
    case SR_INT16_T:
    case SR_INT32_T:
    case SR_INT64_T:
    case SR_UINT8_T:
    case SR_UINT16_T:
    case SR_UINT32_T:
    case SR_UINT64_T:
    case SR_TREE_ITERATOR_T:
        dest->data = source->data;
        dest->type = source->type;
        break;
    default:
        dest->type = source->type;
        break;
    }

    sr_val_set_xpath(dest, source->xpath);
    return rc;
}


static int
wireless_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    char *node;
    struct plugin_ctx *pctx = (struct plugin_ctx *) private_ctx;
    (void) pctx;
    size_t n_mappings;
    int rc = SR_ERR_OK;

    INF("%s", cb_xpath);
    struct list_head list = LIST_HEAD_INIT(list);
    operational_start();
    oper_func func;
    n_mappings = ARR_SIZE(table_operational);

    for (size_t i = 0; i < n_mappings; i++) {
        node = table_operational[i].node;
        func = table_operational[i].op_func;
        INF("\tDiagnostics for: %s", node);
        for (size_t j = 0; j < pctx->interface_count; j++) {
            rc = func(pctx->interface_names[j], &list);
        }
    }

    size_t cnt = 0;
    cnt = list_size(&list);
    INF("Allocating %zu values.", cnt);

    struct value_node *vn;
    size_t j = 0;
    rc = sr_new_values(cnt, values);
    SR_CHECK_RET(rc, exit, "Couldn't create values %s", sr_strerror(rc));

    list_for_each_entry(vn, &list, head) {
        rc = sr_dup_val_data(&(*values)[j], vn->value);
        j += 1;
        sr_free_val(vn->value);
    }

    *values_cnt = cnt;

    list_del(&list);

    if (*values_cnt > 0) {
        INF("[%d - %s]Debug sysrepo values printout: %zu", rc, sr_strerror(rc), *values_cnt);
        for (size_t i = 0; i < *values_cnt; i++){
            sr_print_val(&(*values)[i]);
        }
    }

  exit:
    return rc;
}

static int
get_uci_wireless_devices(struct plugin_ctx *pctx)
{
    const char uci_package_name[] = "wireless";
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    int rc;

    rc = uci_load(pctx->uctx, uci_package_name, &package);
    UCI_CHECK_RET(rc, exit, "[%d] Could not load package %s.", rc, uci_package_name);

    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        if (strcmp("interface", type) == 0) {
            strcpy(pctx->interface_names[pctx->interface_count++], name);
        }
    }

  exit:
    if (package) uci_unload(pctx->uctx, package);
    return rc;
}


int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    INF_MSG("sr_plugin_init_cb for network-plugin");

    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));

    /* Allocate UCI context for uci files. */
    ctx->uctx = uci_alloc_context();
    if (!ctx->uctx) {
        fprintf(stderr, "Can't allocate uci\n");
        goto error;
    }

    *private_ctx = ctx;
    ctx->subscription = subscription;

    rc = get_uci_wireless_devices(ctx);
    UCI_CHECK_RET(rc, error, "[%d] Could not get list of wireless devices from UCI.", rc);

    for (size_t i = 0; i < ctx->interface_count; i++) {
        INF("%s", ctx->interface_names[i]);
    }

    INF_MSG("Connecting to sysrepo ...");
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &ctx->startup_connection);
    SR_CHECK_RET(rc, error, "Error by sr_connect: %s", sr_strerror(rc));


    rc = sr_session_start(ctx->startup_connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &ctx->startup_session);
    SR_CHECK_RET(rc, error, "Error by sr_session_start: %s", sr_strerror(rc));

    rc = sync_datastores(ctx);
    SR_CHECK_RET(rc, error, "Couldn't initialize wirelessx: %s", sr_strerror(rc));
    /* Init wireless. */


    INF_MSG("sr_plugin_init_cb for wireless");
    rc = sr_module_change_subscribe(session, "wireless", wireless_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &subscription);
    SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to operational");
    rc = sr_dp_get_items_subscribe(session, "/wireless:devices-state", wireless_operational_cb, *private_ctx,
                                   SR_SUBSCR_DEFAULT, &subscription);
    SR_CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-terastream finished.");

    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    free(ctx);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx) return;

    struct plugin_ctx *ctx = private_ctx;
    sr_unsubscribe(session, ctx->subscription);
    if (NULL != ctx->startup_session) {
        sr_session_stop(ctx->startup_session);
    }
    if (NULL != ctx->startup_connection) {
        sr_disconnect(ctx->startup_connection);
    }
    if (NULL != ctx->uctx) {
        uci_free_context(ctx->uctx);
    }
    operational_stop();
    free(ctx);

    SRP_LOG_DBG_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void
sigint_handler(__attribute__((unused)) int signum) {
    INF_MSG("Sigint called, exiting...");
    exit_application = 1;
}

int
main() {
    INF_MSG("Plugin application mode initialized");
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    void *private_ctx = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    INF_MSG("Connecting to sysrepo ...");
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &connection);
    SR_CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    INF_MSG("Starting session ...");
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    SR_CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    INF_MSG("Initializing plugin ...");
    rc = sr_plugin_init_cb(session, &private_ctx);
    SR_CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1);  /* or do some more useful work... */
    }

    sr_plugin_cleanup_cb(session, private_ctx);
  cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
}
#endif
