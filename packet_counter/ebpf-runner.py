from bcc import BPF
from time import sleep
from pathlib import Path
import signal

class TerminateSignal(Exception):
    pass

# for handling SIGTERM
def handle_sigterm(signum, frame):
    raise TerminateSignal("Received SIGTERM, terminating...")
    

# load and compiler eBPF program
def load_bpf_program():
    bpf_source = Path("epbf-probe.c").read_text()
    bpf = BPF(text=bpf_source)
    return bpf

# attack eBPF program to specified interface
def attach_xdp_program(bpf: BPF, interface) -> BPF:
    xdp_fn = bpf.load_func("xdp_packet_counter", BPF.XDP)
    bpf.attach_xdp(interface, xdp_fn, 0)
    return bpf

# detach the eBPF program from specified interface
def detach_xdp_program(bpf: BPF, interface):
    bpf.remove_xdp(interface, 0)
    
def main():
    signal.signal(signal.SIGTERM, handle_sigterm)
    
    INTERFACE = "wlp0s20f3"
    
    bpf = load_bpf_program()
    attach_xdp_program(bpf, INTERFACE)
    
    # get packet_count_map defined in eBPF program
    packet_count_map = bpf.get_table("packet_count_map")
    try:
        print("Counting packets, press Ctrl+C to stop...")
        prev_total_packets = 0
        while True:
            sleep(1)
            total_packets = 0

            for key in packet_count_map.keys():
                counter = packet_count_map[key]
                if counter:
                    total_packets += counter.value
                    
            # calculate packets per second
            packets_per_second = total_packets - prev_total_packets
            prev_total_packets = total_packets
            print(f"Packets per second: {packets_per_second}")
    except (KeyboardInterrupt, TerminateSignal) as e:
        print(f"{e}. Interrupting eBPF runner")
    finally:
        print("Detaching eBPF program and exiting")
        detach_xdp_program(bpf, INTERFACE)
    
if __name__ == "__main__":
    main()