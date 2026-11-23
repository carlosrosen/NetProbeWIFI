from src.scanner.icmp import obter_ip_local, varrer_rede_icmp


if __name__ == "__main__":
    print(f"IP local encontrado: {obter_ip_local()}")

    hosts_encontrados = varrer_rede_icmp(quantidade_pings=4)

    if not hosts_encontrados:
        print("\nNenhum host ativo foi encontrado.")
    else:
        print("Hosts que responderam ao ICMP:")
        with open("hosts_ativos_encontrados.txt", "w") as arquivo:
            for host_ativo in hosts_encontrados:
                print(host_ativo.address)
                arquivo.write(f"""
                  address: {host_ativo.address}
                  min_rtt: {host_ativo.min_rtt}
                  avg_rtt: {host_ativo.avg_rtt}
                  max_rtt: {host_ativo.max_rtt}
                  rtts: {host_ativo.rtts}
                  packets_sent: {host_ativo.packets_sent}
                  packets_received: {host_ativo.packets_received}
                  packet_loss: {host_ativo.packet_loss}
                  jitter: {host_ativo.jitter}
                  is_alive: {host_ativo.is_alive}
                  ----------------------------------------------""")
