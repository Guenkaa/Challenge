from scapy.all import sniff, get_if_list
from collections import defaultdict, Counter
from scapy.layers.inet import IP

# Inicializa os contadores
total_packets = 0
protocol_count = defaultdict(int)
origin_ip_counter = Counter()
destination_ip_counter = Counter()

def packet_callback(packet):
    global total_packets

    # Verifica se o pacote contém a camada IP
    if packet.haslayer(IP):
        total_packets += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_len = len(packet)  # Captura o tamanho do pacote

        # Atualiza os contadores de protocolos e IPs
        protocol_count[protocol] += 1
        origin_ip_counter[src_ip] += 1
        destination_ip_counter[dst_ip] += 1

        # Imprime informações sobre o pacote capturado, incluindo o tamanho
        print(f"Capturado pacote # {total_packets}: {src_ip} -> {dst_ip} | Protocolo: {protocol} | Tamanho: {packet_len} bytes")

def start_sniffing(interface="eth0"):  # Use 'eth0' ou a interface correta
    # Verifica quais interfaces estão listadas
    available_interfaces = get_if_list()
    print(f"Interfaces disponíveis no container: {available_interfaces}")

    if interface not in available_interfaces:
        print(f"Erro: Interface '{interface}' não encontrada. As interfaces disponíveis são: {available_interfaces}")
        return

    print(f"Iniciando captura na interface {interface}...")
    # Inicia a captura de pacotes com limite de 30
    sniff(iface=interface, prn=packet_callback, store=False, count=30)

def print_statistics():
    # Mostra as estatísticas de captura ao encerrar o script
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