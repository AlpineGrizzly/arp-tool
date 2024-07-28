# arp-tool
Tool that will monitor arp traffic; Research tool primarily used to learn the libpcap library for myself. 

Primarily followed the tutorial [here](https://www.devdungeon.com/content/using-libpcap-c#google_vignette) and deviated a few times due to deprecated functions and curiosity.

## Requirements
```
sudo apt-get install -y libpcap-dev
```

## Building
```
(cd src	&& make) 
```

## Usage
Walking through the different steps of using the library, getting device info, getting fields from traffic, etc. 
```
./arptool
Devices found
------------------------
** wlp3s0
** any
** lo
** docker0
** bluetooth0
** bluetooth-monitor
** nflog
** nfqueue
** dbus-system
** dbus-session

Getting device info for default cap dev wlp3s0
Device: wlp3s0
Ip address: 192.168.1.0
Subnet mask: 255.255.255.0
```
