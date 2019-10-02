Libvmtrace
===========


Libvmtrace was intended to be a wrapper around libvmi in order to
simplify the process of using VMI-based Breakpoints. The main focus
of libvmtrace is to trace the execution of Linux based virtual machines.
Libvmtrace was used for the following research papers:

* TLSkex: Harnessing virtual machine introspection for decrypting TLS communication
* DroidKex: Fast Extraction of Ephemeral TLS Keys from the Memory of Android Apps
* Architecture for Resource-Aware VMI-based Cloud Malware Analysis
* Sarracenia: Enhancing the Performance and Stealthiness of SSH Honeypots Using Virtual Machine Introspection

[![Build status](https://travis-ci.org/FelixBer/libvmtrace.svg?branch=master)](https://travis-ci.org/FelixBer/libvmtrace)


Installation
============


```
apt-get install libnetfilter-queue-dev libpcap-dev g++ libboost-all-dev automake libtool git libglib2.0-dev g++ libjson-c-dev libxen-dev byacc make netcat libelf-dev libssl-dev flex libdwarf-dev cmake flex bison libglib2.0-dev libvirt-dev libjson-c-dev libyajl-dev colormake libssh-dev libcurl4-openssl-dev uuid-dev
```

Clone and Submodules
============

```
git clone https://github.com/libvmtrace/libvmtrace
cd libvmtrace
git submodule init
git submodule update

cd libvmi
mkdir build
cd build
cmake -DENABLE_KVM=OFF ..
make
make install

cd ../../librdkafka
./configure
make
make install

ldconfig
```

Compile
=======

```
./autogen.sh
./configure
colormake
```

Saracenia JSON
=======

* bp_type (1 -> int3, 2 -> altp2m basic)
* modify_auth (1 -> accept all password as long as username is correct, 0 -> normal way)
* process_change_mode (0 -> off, 1 -> white list, 2 -> black list)
* processes (list of the processes in black/white list)
* ip address

```
{
	"log_dir" : "/root/thesis/log/",
	"sshd_bin_path" : "/root/thesis/openssh-portable-honeypot-server/sshd",
	"sshd_path" : "/usr/sbin/sshd",
	"profile" : "/root/profiles/ubuntu/ubuntu1604-4.4.0-124-generic.json",
	"bp_type" : 1,
	"modify_auth" : 1,
	"process_change_mode" : 0,
	"white_list" : ["wget", "curl"],
	"black_list" : ["make", "gcc", "as", "ld", "gzip", "tar", "ar", "cc1", "install", "bash", "collect2", "cc"],
	"ip" : "192.168.12.51"
}
```
