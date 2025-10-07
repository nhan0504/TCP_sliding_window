# Members
- Name: Abby Tran 
- CS username: ttran44

# Assumptions
## Protocol Design
- **Flow size unit**: Bytes 
- **ACK strategy**: Cumulative ACKs only so out of order ACK won't be acknowledge
- **Window size**: 10 packets at most per window
- **Maximum flows**: Supports up to 8 concurrent flows
- **Packet size**: Fixed at 1000 bytes per packet
- **Timeout**: 100ms for retransmission
- **Maximum retries**: 5 attempts per packet

## Network Configuration
- **Port usage**: Uses DPDK port 1 (second physical interface)
- **MAC addressing**: Server MAC address must be hardcoded in client

## Cloudlab profile
- **Node type**: m510
- **Image**: UBUNTU20-64-STD
- **Topology**: Two nodes with second interfaces (if1) directly connected

# How to run application
## Set up
Run on **both** server and client nodes:
```
sudo apt-get update

sudo apt-get install python3-pip python3-pyelftools libnuma-dev

pip3 install meson

export PATH=~/.local/bin:$PATH

wget https://content.mellanox.com/ofed/MLNX_OFED-4.9-5.1.0.0/MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu20.04-x86_64.tgz

tar -xvzf MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu20.04-x86_64.tgz

cd MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu20.04-x86_64

sudo ./mlnxofedinstall --upstream-libs --dpdk

sudo /etc/init.d/openibd restart

ibv_devinfo

cd ..

git clone https://github.com/DPDK/dpdk

cd dpdk

git checkout releases

meson build -Dexamples=all

cd build

ninja

sudo ninja install

sudo ldconfig

echo 1024 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
```
## Running
### Server
```
cd Server
make
sudo ./build/lab1-server
```

### Client
```
cd Client
make
sudo ./build/lab1-client <num_flow> <flow_size>
```