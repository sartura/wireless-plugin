# Sysrepo Wireless plugin (DT)

## Introduction

This Sysrepo plugin is responsible for bridging OpenWrt [**UCI**]() (Unified Configuration Interface) and Sysrepo/YANG datastore configuration for wireless interfaces.

## Development Setup

Setup the development environment using the provided [`setup-dev-sysrepo`](https://github.com/sartura/setup-dev-sysrepo) scripts. This will build all the necessary components and initialize a sparse OpenWrt filesystem.

Subsequent rebuilds of the plugin may be done by navigating to the plugin source directory and executing:

```
$ export SYSREPO_DIR=${HOME}/code/sysrepofs
$ cd ${SYSREPO_DIR}/repositories/plugins/wireless-plugin

$ rm -rf ./build && mkdir ./build && cd ./build
$ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_PREFIX_PATH=${SYSREPO_DIR} \
		-DCMAKE_INSTALL_PREFIX=${SYSREPO_DIR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..
-- The C compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
[...]
-- Configuring done
-- Generating done
-- Build files have been written to: ${SYSREPO_DIR}/repositories/plugins/wireless-plugin/build

$ make && make install
[...]
[ 75%] Building C object CMakeFiles/sysrepo-plugin-dt-wireless.dir/src/utils/memory.c.o
[100%] Linking C executable sysrepo-plugin-dt-wireless
[100%] Built target sysrepo-plugin-dt-wireless
[100%] Built target sysrepo-plugin-dt-wireless
Install the project...
-- Install configuration: "Debug"
-- Installing: ${SYSREPO_DIR}/bin/sysrepo-plugin-dt-wireless
-- Set runtime path of "${SYSREPO_DIR}/bin/sysrepo-plugin-dt-wireless" to ""

$ cd ..
```

Before using the plugin it is necessary to install relevant YANG modules. For this particular plugin, the following commands need to be invoked:

```
$ cd ${SYSREPO_DIR}/repositories/plugins/wireless-plugin
$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$ sysrepoctl -i ./yang/terastream-wireless@2017-08-08.yang
```

## YANG Overview

The `terastream-wireless` YANG module with the `ts-ws` prefix consists of the following `container` paths:

* `/terastream-wireless:apsteering` — configuration state data for apsteering
* `/terastream-wireless:bandsteering` — configuration state data for bandsteering
* `/terastream-wireless:devices` — configuration state data for devices

The following items are not configurational i.e. they are `operational` state data:

* `/terastream-wireless:devices-state` — operational data for devices

## Running and Examples

This plugin is installed as the `sysrepo-plugin-dt-wireless` binary to `${SYSREPO_DIR}/bin/` directory path. Simply invoke this binary, making sure that the environment variables are set correctly:

```
$ sysrepo-plugin-dt-wireless
[INF]: Applying scheduled changes.
[INF]: No scheduled changes.
[INF]: Session 45 (user "...") created.
[INF]: plugin: start session to startup datastore
[INF]: Session 46 (user "...") created.
[INF]: plugin: running DS is empty, loading data from UCI
[INF]: There are no subscribers for changes of the module "terastream-wireless" in running DS.
[INF]: plugin: subscribing to module change
[INF]: plugin: subscribing to get oper items
[INF]: plugin: plugin init done
[...]
```

Output from the plugin is expected; the plugin has loaded UCI configuration at `${SYSREPO_DIR}/etc/config/wireless` into the `startup` datastore. We can confirm this by invoking the following commands:

```
$ cat ${SYSREPO_DIR}/etc/config/wireless
config wifi-status 'status'
	option wlan '1'
	option wps '1'
	option sched_status '0'
	option schedule '0'

config bandsteering 'bandsteering'
	option enabled '0'
	option policy '0'

config wifi-device 'wl0'
	option type 'broadcom'
	option country 'EU/13'
	option band 'a'
	option bandwidth '80'
	option hwmode 'auto'
	option channel 'auto'
	option scantimer '15'
	option wmm '1'
	option wmm_noack '0'
	option wmm_apsd '1'
	option txpower '100'
	option rateset 'default'
	option frag '2346'
	option rts '2347'
	option dtim_period '1'
	option beacon_int '100'
	option rxchainps '0'
	option rxchainps_qt '10'
	option rxchainps_pps '10'
	option rifs '0'
	option rifs_advert '0'
	option maxassoc '32'
	option beamforming '1'
	option doth '1'
	option dfsc '1'

config wifi-iface
	option device 'wl0'
	option network 'lan'
	option mode 'ap'
	option ssid 'PANTERA-7858'
	option encryption 'psk2'
	option cipher 'auto'
	option key 'keykeykey'
	option gtk_rekey '3600'
	option macfilter '0'
	option wps_pbc '1'
	option wmf_bss_enable '1'
	option bss_max '32'
	option ifname 'wl0'

config wifi-device 'wl1'
	option type 'broadcom'
	option country 'EU/13'
	option band 'b'
	option bandwidth '20'
	option hwmode 'auto'
	option channel 'auto'
	option scantimer '15'
	option wmm '1'
	option wmm_noack '0'
	option wmm_apsd '1'
	option txpower '100'
	option rateset 'default'
	option frag '2346'
	option rts '2347'
	option dtim_period '1'
	option beacon_int '100'
	option rxchainps '0'
	option rxchainps_qt '10'
	option rxchainps_pps '10'
	option rifs '0'
	option rifs_advert '0'
	option maxassoc '32'
	option doth '0'

config wifi-iface
	option device 'wl1'
	option network 'lan'
	option mode 'ap'
	option ssid 'PANTERA-7858'
	option encryption 'psk2'
	option cipher 'auto'
	option key 'rootrootroot'
	option gtk_rekey '3600'
	option macfilter '0'
	option wps_pbc '1'
	option wmf_bss_enable '1'
	option bss_max '32'
	option ifname 'wl1'

config apsteering 'apsteering'
	option enabled '0'

$ sysrepocfg -X -d startup -f json -m 'terastream-wireless'
{
  "terastream-wireless:apsteering": {
    "enabled": false
  },
  "terastream-wireless:bandsteering": {
    "enabled": false,
    "policy": false
  },
  "terastream-wireless:devices": {
    "device": [
      {
        "name": "wl0",
        "type": "broadcom",
        "country": "EU/13",
        "frequencyband": "5",
        "bandwidth": 80,
        "hwmode": "auto",
        "channel": "auto",
        "scantimer": 15,
        "wmm": true,
        "wmm_noack": false,
        "wmm_apsd": true,
        "txpower": 100,
        "rateset": "default",
        "frag": 2346,
        "rts": 2347,
        "dtim_period": 1,
        "beacon_int": 100,
        "rxchainps": false,
        "rxchainps_qt": 10,
        "rxchainps_pps": 10,
        "rifs": false,
        "rifs_advert": false,
        "maxassoc": 32,
        "beamforming": true,
        "doth": 1,
        "dfsc": true,
        "interface": [
          {
            "name": "cfg043579",
            "network": "lan",
            "mode": "ap",
            "ssid": "PANTERA-7858",
            "encryption": "psk2",
            "cipher": "auto",
            "key": "keykeykey",
            "gtk_rekey": 3600,
            "macfilter": 0,
            "wps_pbc": true,
            "wmf_bss_enable": true,
            "bss_max": 32,
            "ifname": "wl0"
          }
        ]
      },
      {
        "name": "wl1",
        "type": "broadcom",
        "country": "EU/13",
        "frequencyband": "2.4",
        "bandwidth": 20,
        "hwmode": "auto",
        "channel": "auto",
        "scantimer": 15,
        "wmm": true,
        "wmm_noack": false,
        "wmm_apsd": true,
        "txpower": 100,
        "rateset": "default",
        "frag": 2346,
        "rts": 2347,
        "dtim_period": 1,
        "beacon_int": 100,
        "rxchainps": false,
        "rxchainps_qt": 10,
        "rxchainps_pps": 10,
        "rifs": false,
        "rifs_advert": false,
        "maxassoc": 32,
        "doth": 0,
        "interface": [
          {
            "name": "cfg063579",
            "network": "lan",
            "mode": "ap",
            "ssid": "PANTERA-7858",
            "encryption": "psk2",
            "cipher": "auto",
            "key": "rootrootroot",
            "gtk_rekey": 3600,
            "macfilter": 0,
            "wps_pbc": true,
            "wmf_bss_enable": true,
            "bss_max": 32,
            "ifname": "wl1"
          }
        ]
      }
    ]
  }
}
```

Provided output suggests that the plugin has correctly initialized Sysrepo `startup` datastore with appropriate data transformations. It can be seen that all containers have been populated.

Changes to the `running` datastore can be done manually by invoking the following command:

```
$ sysrepocfg -E -d running -f json -m 'terastream-wireless'
[...interactive...]
{
  [...]
  "terastream-wireless:devices": {
    "device": [
	  [...]
      {
        "name": "wl1",
        [...]
        "interface": [
          {
            "name": "cfg063579",
            "network": "lan",
            "mode": "ap",
            "ssid": "PANTERA-7858",
            "encryption": "psk2",
            "cipher": "auto",
            "key": "rootrootroot",
            "gtk_rekey": 3600,
            "macfilter": 0, // => 1
            "wps_pbc": true,
            "wmf_bss_enable": true,
            "bss_max": 32,
            "ifname": "wl1"
          }
        ]
      }
    ]
  }
}
```

Alternatively, instead of changing the entire module data with `-m 'terastream-wireless'` we can change data on a certain XPath with e.g. `-x '/terastream-wireless:devices'`.

After executing previous command, the following should appear at plugin binary standard output:

```
[INF]: Processing "terastream-wireless" "change" event with ID 1 priority 0 (remaining 1 subscribers).
[INF]: plugin: module_name: terastream-wireless, xpath: /terastream-wireless:*//*, event: 1, request_id: 1
[DBG]: plugin: uci_path: wireless.cfg043579.macfilter; prev_val: 0; node_val: 1; operation: 1
[DBG]: plugin: uci_path: wireless.cfg063579.macfilter; prev_val: 0; node_val: 1; operation: 1
[INF]: Successful processing of "change" event with ID 1 priority 0 (remaining 0 subscribers).
[INF]: Processing "terastream-wireless" "done" event with ID 1 priority 0 (remaining 1 subscribers).
[INF]: plugin: module_name: terastream-wireless, xpath: /terastream-wireless:*//*, event: 2, request_id: 1
[...]
[INF]: Successful processing of "done" event with ID 1 priority 0 (remaining 0 subscribers).
```

The datastore change operation should be reflected in the `/etc/config/wireless` UCI file:

```
$ cat ${SYSREPO_DIR}/etc/config/wireless | grep accept_ra
        option macfilter 'enabled'
        option macfilter 'enabled'
```

In constrast to the configuration state data, using `sysrepocfg` we can access `operational` state data. For example:

```
$ sysrepocfg -X -d operational -f json -x '/terastream-wireless:devices-state'
{
  "terastream-wireless:devices-state": {
    "device": [
      {
        "name": "wl0",
        "channel": "100",
        "ssid": "PANTERA-7666",
        "encryption": "psk2",
        "up": true
      }
    ]
  }
}
```

This data is usually provided by certain `ubus` methods which can be acessed via the `ubus` command line utility:

```
$ ubus call router.wireless status
{
        "wldev": "wl0",
        "radio": 1,
        "ssid": "PANTERA-7666",
        "bssid": "00:22:07:67:78:57",
        "encryption": "WPA2 PSK",
        "frequency": 5,
        "channel": 100,
        "bandwidth": 80,
        "noise": -74,
        "rate": 433
}
```