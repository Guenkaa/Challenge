from scapy.all import sniff, get_if_list
from collections import defaultdict, Counter
from scapy.layers.inet import IP

total_packets = 0
protocol_count = defaultdict(int)
origin_ip_counter = Counter()
destination_ip_counter = Counter()

def packet_callback(packet):
    """
    Processa cada pacote capturado, contabilizando total, protocolo,
    IPs de origem e destino, e imprime detalhes do pacote.
    """
    global total_packets

    if packet.haslayer(IP):
        total_packets += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_len = len(packet)

        protocol_count[protocol] += 1
        origin_ip_counter[src_ip] += 1
        destination_ip_counter[dst_ip] += 1

        print(f"Capturado pacote # {total_packets}: {src_ip} -> {dst_ip} | Protocolo: {protocol} | Tamanho: {packet_len} bytes")

def start_sniffing(interface="eth0"):
    """
    Inicia a captura de pacotes na interface de rede especificada.
    Verifica se a interface existe e limita a captura a 30 pacotes.
    """
    available_interfaces = get_if_list()
    print(f"Interfaces disponíveis no container: {available_interfaces}")

    if interface not in available_interfaces:
        print(f"Erro: Interface '{interface}' não encontrada. As interfaces disponíveis são: {available_interfaces}")
        return

    print(f"Iniciando captura na interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=False, count=30)

def print_statistics():
    """
    Exibe estatísticas resumidas da captura: total de pacotes,
    distribuição por protocolo e os IPs mais frequentes.
    """
    print("\nEstatísticas de Captura:")
    print(f"Total de pacotes capturados: {total_packets}")
    print(f"Pacotes por protocolo: {dict(protocol_count)}")
    print(f"Top 5 IPs de origem: {origin_ip_counter.most_common(5)}")
    print(f"Top 5 IPs de destino: {destination_ip_counter.most_common(5)}")

try:
    start_sniffing()
    print_statistics()
except KeyboardInterrupt:
    print_statistics()
