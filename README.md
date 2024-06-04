# XDP Program to Drop TCP Packets on Specific Port

This project contains an eBPF/XDP program written in C and Go to drop TCP packets on a specific port. The C code defines the XDP program, while the Go code is used to manage the eBPF program and handle events.

## Prerequisites

- **Go Language**: Make sure Go is installed on your system. You can download it from the [official Go website](https://golang.org/dl/).
- **C Compiler**: Ensure you have a C compiler installed. GCC or Clang is recommended.
- **libbpf**: Install libbpf for eBPF support. You can follow instructions from the [libbpf repository](https://github.com/libbpf/libbpf).
- **bpftool**: Install bpftool to manage BPF programs. You can follow instructions from the [bpftool repository](https://github.com/libbpf/bpftool).
- **Cilium ebpf Go Library**: Install the Cilium ebpf Go library using:
    ```sh
    go get github.com/cilium/ebpf
    ```
- **Linux Kernel Headers**: Make sure you have the appropriate kernel headers installed for your Linux distribution.

## How to Run the Code

### Build the eBPF Object File

First, compile the C code into an eBPF object file:
```sh
clang -O2 -target bpf -c drop_tcp_port.c -o drop_tcp_port.o
```
### Build the Go Program

Build the Go program using the following command:

```sh
sudo /usr/local/go/bin/go build -o xdp_prog main.go
```
## Run the Program

Run the compiled Go program with the desired port number (default is 4040). For example, to use port 8080:

```sh
sudo ./xdp_prog 8080
```
## Testing

To verify that the XDP program is dropping packets on the specified port, use tcpdump to monitor the network traffic on the loopback interface:

```sh
sudo tcpdump -i lo tcp port <PORT>
```
## Code Overview

### C Code (drop_tcp_port.c)

The C code defines an XDP program that filters and drops TCP packets based on a specific port number. It utilizes eBPF maps to store the port number and trace events.

### Go Code (main.go)

The Go code loads the eBPF program, attaches it to the network interface, and handles events from the eBPF program. It updates statistics and prints them to the console.

## XDP Program Workflow

- **Packet Parsing**: The XDP program parses incoming packets to identify TCP packets.
- **Port Matching**: The program checks if the destination port matches the specified port.
- **Action**: If a match is found, the packet is dropped; otherwise, it is passed.
- **Event Reporting**: The program reports events (enter, drop, pass) and processing times via a perf event array.

### Event Handling

The Go program reads events from the eBPF program using a perf event reader. It updates counters and calculates average processing times for passed and dropped packets.

## Conclusion

This project demonstrates how to use eBPF/XDP to filter network traffic at a very low level. By customizing the port number, you can drop specific TCP packets efficiently.
