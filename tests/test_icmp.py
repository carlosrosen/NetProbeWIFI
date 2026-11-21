from src.scanner.icmp import get_local_ip, scan_icmp_network



if __name__ == "__main__":
    
    print(f'ip_local encontrado: {get_local_ip()}')
    
    hosts_encontrados = scan_icmp_network(count=4)
    
    if(len(hosts_encontrados) == 0 ):
        print('\nNenhum host ativo foi encontrado.')
    else:
        print('Hosts que responderam ao icmp: ')
        with open('hosts_ativos_encontrados.txt','w') as fp:
            for host in hosts_encontrados:
                print(host.address)
                fp.write(f'''
                  address: {host.address}
                  min_rtt: {host.min_rtt}
                  avg_rtt: {host.avg_rtt}
                  max_rtt: {host.max_rtt}
                  rtts: {host.rtts}
                  packets_sent: {host.packets_sent}
                  packets_received: {host.packets_received}
                  packet_loss: {host.packet_loss}
                  jitter: {host.jitter}
                  is_alive: {host.is_alive}
                  ----------------------------------------------''')
    
