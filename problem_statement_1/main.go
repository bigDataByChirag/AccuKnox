package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	TYPE_ENTER = 1
	TYPE_DROP  = 2
	TYPE_PASS  = 3
)

// Define the structure of an event from the eBPF program
type event struct {
	TimeSinceBoot  uint64
	ProcessingTime uint32
	Type           uint8
}

const ringBufferSize = 128

// Define a ring buffer to store processing times
type ringBuffer struct {
	data    [ringBufferSize]uint32
	pointer int
	filled  bool
}

// Add a value to the ring buffer
func (rb *ringBuffer) add(val uint32) {
	if rb.pointer < ringBufferSize {
		rb.pointer++
	} else {
		rb.filled = true
		rb.pointer = 1
	}
	rb.data[rb.pointer-1] = val
}

// Calculate the average value in the ring buffer
func (rb *ringBuffer) avg() float32 {
	if rb.pointer == 0 {
		return 0
	}
	sum := uint32(0)
	for _, val := range rb.data {
		sum += uint32(val)
	}
	if rb.filled {
		return float32(sum) / float32(ringBufferSize)
	}
	return float32(sum) / float32(rb.pointer)
}

func main() {
	// Load the eBPF program from an object file
	spec, err := ebpf.LoadCollectionSpec("drop_tcp_port.o")
	if err != nil {
		panic(err)
	}

	// Create a new eBPF collection from the loaded spec
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new collection: %v\n", err))
	}
	defer coll.Close()

	// Retrieve the XDP program from the collection
	prog := coll.Programs["xdp_prog"]
	if prog == nil {
		panic("No program named 'xdp_prog' found in collection")
	}

	// Specify the network interface to attach the XDP program to
	iface := "lo"
	if iface == "" {
		panic("No interface specified. Please set the INTERFACE environment variable to the name of the interface to be used")
	}
	ifaceIdx, err := net.InterfaceByName(iface)
	if err != nil {
		panic(fmt.Sprintf("Failed to get interface %s: %v\n", iface, err))
	}

	// Attach the XDP program to the network interface
	opts := link.XDPOptions{
		Program:   prog,
		Interface: ifaceIdx.Index,
	}
	lnk, err := link.AttachXDP(opts)
	if err != nil {
		panic(fmt.Sprintf("Failed to attach XDP program: %v\n", err))
	}
	defer lnk.Close()

	// Set the port number to filter packets on, defaulting to 4040
	port := uint16(4040)
	if len(os.Args) > 1 {
		parsedPort, err := strconv.Atoi(os.Args[1])
		if err == nil && parsedPort > 0 && parsedPort <= 65535 {
			port = uint16(parsedPort)
		}
	}

	// Update the port map in the eBPF program with the chosen port
	portMap := coll.Maps["port_map"]
	if err := portMap.Put(uint32(0), port); err != nil {
		panic(fmt.Sprintf("Failed to update port map: %v\n", err))
	}

	fmt.Println("Successfully loaded and attached BPF program.")

	// Create a perf event reader to read events from the eBPF program
	outputMap := coll.Maps["output_map"]
	perfEvent, err := perf.NewReader(outputMap, 4096)
	if err != nil {
		panic(fmt.Sprintf("Failed to create perf event reader: %v\n", err))
	}
	defer perfEvent.Close()

	// Buckets to keep track of event counts
	buckets := map[uint8]uint32{
		TYPE_ENTER: 0,
		TYPE_DROP:  0,
		TYPE_PASS:  0,
	}

	// Ring buffers to store processing times for passed and dropped packets
	processingTimePassed := &ringBuffer{}
	processingTimeDropped := &ringBuffer{}

	// Goroutine to read and process events from the perf event reader
	go func() {
		for {
			record, err := perfEvent.Read()
			if err != nil {
				fmt.Println(err)
				continue
			}

			// Parse the event from the raw sample
			var e event
			if len(record.RawSample) < 12 {
				fmt.Println("Invalid sample size")
				continue
			}
			e.TimeSinceBoot = binary.LittleEndian.Uint64(record.RawSample[:8])
			e.ProcessingTime = binary.LittleEndian.Uint32(record.RawSample[8:12])
			e.Type = uint8(record.RawSample[12])
			buckets[e.Type]++

			// Update the ring buffers with processing times
			if e.Type == TYPE_ENTER {
				continue
			}
			if e.Type == TYPE_DROP {
				processingTimeDropped.add(e.ProcessingTime)
			} else if e.Type == TYPE_PASS {
				processingTimePassed.add(e.ProcessingTime)
			}

			// Clear the console and print the updated statistics
			fmt.Print("\033[H\033[2J")
			fmt.Printf("total: %d. passed: %d. dropped: %d. passed processing time avg (ns): %f. dropped processing time avg (ns): %f\n", buckets[TYPE_ENTER], buckets[TYPE_PASS], buckets[TYPE_DROP], processingTimePassed.avg(), processingTimeDropped.avg())
		}
	}()

	// Wait for a termination signal (e.g., Ctrl+C) to exit the program
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
