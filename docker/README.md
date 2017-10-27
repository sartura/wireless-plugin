docker for SIP Sysrepo plugin.

## build dockerfile

```
$ docker build -t sysrepo/sysrepo-netopeer2:wireless -f Dockerfile .
```

## run dockerfile with supervisor

```
$ docker run -i -t --name sysrepo2 -p 830:830 --rm sysrepo/sysrepo-netopeer2:wireless
```

## run dockerfile without supervisor

```
$ docker run -v /opt/yang:/opt/fork -i -t --name wireless_plugin --rm sysrepo/sysrepo-netopeer2:wireless bash
$ ubusd &
$ rpcd &
$ sysrepod
$ sysrepo-plugind
$ netopeer2-server
```
