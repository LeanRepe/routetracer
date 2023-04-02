import re
import json
import ipaddress
import datetime
import logging
import time
from sys import exit
from mtcollector import MTCollector
from ipaddress import AddressValueError

main_logger = logging.getLogger(__name__)
main_logger.setLevel(logging.DEBUG)
logger_handler = logging.FileHandler(f'{__name__}.log', mode='w')
logger_formatter = logging.Formatter('%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s')
logger_handler.setFormatter(logger_formatter)
main_logger.addHandler(logger_handler)

with open('examples/example-phphl_pe1', 'r') as file:
    output = file.readlines()
    file.close()


class Regex:
    rt_next_hop = r'^\s+(\d+.\d+.\d+.\d+),.*$'
    rt_entry = r'^Routing entry for (\S+)$'
    nhop_interface = r'^\s+\S+\s+connected,\s+via\s+(\S+)$'
    tip_desc = r''
    cef_vrf_subnet = r'^(\d+.\d+.\d+.\d+/\d+),\sversion.*$'
    cef_nhop = r'^\s+via\s(BVI\d+|\d+.\d+.\d+.\d+/\d+|TenGigE\S+|Giga\S+),.*$'
    cef_int_nhop = r'^\s+\d+\s+\S+\s+(\S+)\s+(\S+)\s+$'
    tunnel_desc = r'^.*To\s+(\S+):Tunnel-ip\d+$'
    connected_route = r'^^L\s+(\S+)\sis directly connected, \S+\s+(\S+)$'
    isis_source = r'^\s+src\s+(\S+)\.\S+,.*$'


def new_edge(system_dict: dict, output_line: list) -> None:
    edge = output_line[2]
    interface = output_line[3]
    metric = output_line[1]
    if edge not in system_dict:
        system_dict[edge] = {'nhi': interface, 'metric': metric}


def nhop_system(system_dict: dict, output_line: list) -> None:
    nh_systemp = output_line[0]
    metric = output_line[1]
    edge = output_line[2]
    if nh_systemp not in system_dict:
        system_dict[nh_systemp] = []
    system_dict[nh_systemp].append((edge, metric))


def get_system(output: str) -> str:
    system_id = ''
    for lines in output.splitlines():
        line = lines.split()
        if '--' in line:
            system_id = line[0]
            break
    return system_id


def isis_topology_trace(topo_dict: dict, source: str, dest: str, hop: int = 0) -> list:
    hop_list = []
    current_node = source
    previous_node = ''
    main_logger.debug(f'Starting ISIS topology trace')
    while True:
        if current_node == dest:
            break
        else:
            if current_node in topo_dict:
                if dest in topo_dict[current_node]['nhsystems']:
                    edge = topo_dict[current_node]['nhsystems'][dest][0][0]
                    nhi = topo_dict[current_node]['edges'][edge]['nhi']
                    main_logger.debug(f'Current node: {current_node}, Edge: {edge}')
                    if hop > 0:
                        if previous_node != '':
                            ing_if = topo_dict[current_node]['edges'][previous_node]['nhi']
                        else:
                            ing_if = ''
                        hop_dict = {hop: {'node': current_node, 'egress_if': nhi, 'ingress_if': ing_if}}
                    else:
                        hop_dict = {hop: {'node': current_node, 'egress_if': nhi, 'ingress_if': '-----'}}
                    hop_list.append(hop_dict)
                    previous_node = current_node
                    current_node = edge
                    hop += 1
                    main_logger.debug(f'{hop_dict}')
                elif dest in topo_dict[current_node]['edges']:
                    nhi = topo_dict[current_node]['edges'][dest]['nhi']
                    ing_if = topo_dict[current_node]['edges'][previous_node]['nhi']
                    hop_dict = {hop: {'node': current_node, 'egress_if': nhi, 'ingress_if': ing_if}}
                    ing_ifz = topo_dict[dest]['edges'][current_node]['nhi']
                    end_dict = {hop+1: {'node': dest, 'egress_if': '-----', 'ingress_if': ing_ifz}}
                    main_logger.debug(f'Current node: {current_node}, End: {dest}')
                    main_logger.debug(f'{hop_dict}\n{end_dict}')
                    hop_list.append(hop_dict)
                    hop_list.append(end_dict)
                    current_node = dest
                else:
                    main_logger.error(f'Unable to trace - {dest} not part of the topology')
                    exit(1)
            else:
                main_logger.error(f'Unable to trace - {current_node} not part of the topology')
                exit(1)
    return hop_list


def topology_population(topology_dict: dict, output: str) -> None:
    system = get_system(output)
    if system not in topology_dict:
        topology_dict[system] = {'edges': {}, 'nhsystems': {}}
    for index, lines in enumerate(output.splitlines()):
        no_newline_output = lines.split()
        if len(no_newline_output) > 2 and index > 4:
            if '--' not in no_newline_output:
                if no_newline_output[0] == no_newline_output[2]:
                    new_edge(topology_dict[system]['edges'], no_newline_output)
                else:
                    if index > 1:
                        nhop_system(topology_dict[system]['nhsystems'], no_newline_output)


def cef_nhop(output: str) -> tuple:
    subnet = ''
    nhop_ip = ''
    nhop_int = ''
    nhop_addr = ''
    for line in output.splitlines():
        if re.match(Regex.cef_vrf_subnet, line, re.M):
            subnet = re.match(Regex.cef_vrf_subnet, line, re.M).group(1)
        elif re.match(Regex.cef_nhop, line, re.M):
            nhop_ip = re.match(Regex.cef_nhop, line, re.M).group(1)
        elif re.match(Regex.cef_int_nhop, line, re.M):
            nhop_int = re.match(Regex.cef_int_nhop, line, re.M).group(1)
            nhop_addr = re.match(Regex.cef_int_nhop, line, re.M).group(2)
    main_logger.debug(f'CEF PARSER{"-"*30}\nSubnet: {subnet}, '
              f'NHOP: {nhop_ip}, NHOP INT: {nhop_int}, NHOP ADDR: {nhop_addr}')
    if '0.0.0.0' in subnet:
        if '/32' in subnet and 'null0' in nhop_addr:
            return 'null0', 'no-hop'
        else:
            return 'default', 'no-nhop'
    else:
        return nhop_ip, nhop_int


def first_hop(output: str) -> str:
    hop = ''
    for lines in output.splitlines():
        no_newline_output = lines.split()
        main_logger.debug(f'FISRT HOP Parsed output: {no_newline_output}\n')
        if len(no_newline_output) > 2:
            if no_newline_output[0] == no_newline_output[2]:
                hop = no_newline_output[0]
    return hop


def tunnel_description(output: str) -> str:
    vrouter = ''
    for line in output.splitlines():
        if re.match(Regex.tunnel_desc, line, re.M):
            vrouter = re.match(Regex.tunnel_desc, line, re.M).group(1)
    return vrouter


def is_summary(subnet: str) -> bool:
    netaddress = ipaddress.IPv4Network(subnet, strict=True)
    if netaddress.prefixlen < 24:
        return True
    else:
        return False


def check_ip(ipaddr: str) -> bool:
    if '/' in ipaddr:
        try:
            ipaddress.IPv4Network(ipaddr)
            return True
        except AddressValueError:
            return False
    else:
        try:
            ipaddress.IPv4Address(ipaddr)
            return True
        except AddressValueError:
            return False


def single_device_collection(node_ip: str, show: str) -> str:
    global username
    global password
    global socks_proxy
    packed_output = MTCollector(node_ip, show, user=username, paswd=password, sock_proxy=socks_proxy)
    if 'not_connected' in packed_output:
        main_logger.error(f'Unable to connect to device {node_ip}')
        exit(1)
    else:
        unpacked_output = packed_output[node_ip][0][show]
        return unpacked_output


def gather_topology(pe_dict: dict, topo_dict: dict, target_device: str = None) -> dict:
    global username
    global password
    global socks_proxy
    show_topo = 'show isis instance CORE topology'
    main_logger.info(f"Gathering ISIS topology - if it's a full discovery could take some time")
    if target_device is None:
        output_isis = MTCollector(pe_dict, show_topo, user=username, paswd=password,
                                  sock_proxy=socks_proxy, max_threads=3)
        for device in output_isis:
            if device != 'not_connected':
                topology_population(topo_dict, output_isis[device][0][show_topo])
            else:
                if device in pe_dict:
                    lo10 = pe_dict[device]
                    single_ouptut = single_device_collection(lo10, show_topo)
                    main_logger.debug(f'"NOT_CONNECTED" OUTPUT COLLECTION\n{"-"*30}')
                    main_logger.debug(f'output {show_topo} for {device}:\n{"-" * 30}\n{single_ouptut}\n\n')
                    if device in single_ouptut:
                        topology_population(topo_dict, single_ouptut)
                    else:
                        main_logger.error(f'WARNING: Topology incomplete, unable to reach {device}')
    else:
        if target_device in pe_dict:
            lo10 = pe_dict[target_device]
            single_ouptut = single_device_collection(lo10, show_topo)
            main_logger.debug(f'TARGETED OUTPUT COLLECTION\n{"-" * 30}')
            main_logger.debug(f'output {show_topo} for {target_device}:\n{"-" * 30}\n{single_ouptut}\n\n')
            try:
                topology_population(topo_dict, single_ouptut)
            except TypeError:
                main_logger.error(f'WARNING: Topology incomplete, unable to reach {target_device}')
    return topo_dict


def run(start_node: str, ip: str, topo_dict: dict, source_ip: str = None, vrf: str = None) -> tuple:
    if source_ip is None:
        source_ip = get_conn_int(source, vrf, full_db)
    if check_ip(start_node):
        start_node_ip = start_node
        start_node = [node for node, ip in full_db.items() if ip == start_node_ip][0]
    else:
        start_node_ip = full_db[start_node]
    if vrf is not None:
        show_cef = f'show cef vrf {vrf} {ip} detail'
        show_cef_rpf = f'show cef vrf {vrf} {source_ip} detail'
    else:
        show_cef = f'show cef {ip} detail'
        show_cef_rpf = f'show cef {source_ip} detail'
    if 'CSR' in start_node:
        main_logger.info(f'Running trace from/to CSR')
        isis_topo = single_device_collection(start_node_ip, 'show isis topology')
        isis_hop = first_hop(isis_topo)
        results = full_trace(topo_dict, show_cef, start_node, isis_hop=isis_hop)
        end_node, end_ip, hop_list = results
        rpf_results = full_trace(topo_dict, show_cef_rpf, end_node, isis_hop=isis_hop)
    else:
        main_logger.info(f'Running trace from/to PE or vRouter')
        results = full_trace(topo_dict, show_cef, start_node)
        end_node, end_ip, hop_list = results
        rpf_results = full_trace(topo_dict, show_cef_rpf, end_node)
    return results, rpf_results


def full_trace(topo_dict: dict, show_cef: str, start_node: str, isis_hop: str = None) -> tuple:
    hop_list = []
    current_node = start_node
    current_ip = [ip for sys, ip in full_db.items() if start_node == sys][0]
    end_node = ''
    end_ip = ''
    main_logger.info(f'Starting Full Trace - start node: {start_node}')
    tunn_num = ''
    while True:
        cef_output = single_device_collection(current_ip, show_cef)
        main_logger.debug(f'CEF OUTPUT - {current_node}\n{"-" * 30}\n{cef_output}\n\n')
        cef_hop_net, cef_int = cef_nhop(cef_output)
        if end_node != '':
            break
        else:
            if 'default' in cef_hop_net:
                main_logger.error(f'Unable to trace to specific network, cef next-hop towards default route')
                exit(1)
            elif 'null0' in cef_hop_net:
                main_logger.error(f'Null0 route in {current_node} for the traced IP. Please review the routing!')
                exit(1)
            else:
                if 'recursive' in cef_int:
                    if check_ip(cef_hop_net):
                        if 'CSR' in current_node:
                            isis_hop_ip = full_db[isis_hop]
                            next_node = isis_src(isis_hop_ip, cef_hop_net)
                            next_ip = full_db[next_node]
                            if len(hop_list) > 0:
                                current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                                temp_list = isis_topology_trace(topo_dict, isis_hop, next_node, hop=current_hop)
                                hop_list = hop_list + temp_list
                            else:
                                hop_list = isis_topology_trace(topo_dict, isis_hop, next_node)
                        elif 'CS-PE' in current_node:
                            next_node = isis_src(current_ip, cef_hop_net)
                            next_ip = full_db[next_node]
                            if len(hop_list) > 0:
                                current_hop = [x for x,y in hop_list[-1].items()][0] + 1
                                new_vrouter = {current_hop:
                                    {
                                        'node': current_node,
                                        'ingress_if': 'TU-IP',
                                        'egress_if': 'TU-IP'
                                    }
                                }
                                hop_list.append(new_vrouter)
                            else:
                                current_hop = 0
                                new_vrouter = {current_hop:
                                                   {
                                                       'node': current_node,
                                                       'ingress_if': '---',
                                                       'egress_if': 'TU-IP'
                                                   }
                                }
                                hop_list.append(new_vrouter)
                        else:
                            next_node = isis_src(current_ip, cef_hop_net)
                            next_ip = full_db[next_node]
                            main_logger.debug(f'ISIS Topology trace from {current_node} to {next_node}\n')
                            if len(hop_list) > 0:
                                current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                                temp_list = isis_topology_trace(topo_dict, current_node, next_node, hop=current_hop)
                                hop_list = hop_list + temp_list
                            else:
                                hop_list = isis_topology_trace(topo_dict, current_node, next_node)
                            if next_node == isis_hop:
                                end_node = next_node
                                end_ip = next_ip
                    elif re.search(r'TenGi|Giga|BV', cef_hop_net):
                        end_ip = current_ip
                        end_node = current_node
                    else:
                        main_logger.error(f'Unable to trace cef next_hop {cef_hop_net}, cef interface {cef_int}')
                        exit(1)
                elif 'tunnel' in cef_int:
                    show_desc = f'show interface {cef_int} | i Description'
                    tunnel_descrip = single_device_collection(current_ip, show_desc)
                    next_node = tunnel_description(tunnel_descrip)
                    tunn_num = cef_int.split('ip')[1]
                    main_logger.debug(f'---- NHOP Tunnel detected ---\nOutput\n{"-"*30}\n{tunnel_descrip}\n'
                                  f'Parsed\n{"-"*30}\nNext Node: {next_node}, Tunnel Number: {tunn_num} ')
                    if 'CS-PE' in next_node:
                        if len(hop_list) > 0:
                            current_hop = [x for x, y in hop_list[-1].items()][0]
                            if current_node == hop_list[-1][current_hop]['node']:
                                hop_list[-1][current_hop]['egress_if'] = f'{"TU-"+tunn_num}'
                    else:
                        if len(hop_list) > 0:
                            current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                            new_vrouter = {current_hop:
                                {
                                    'node': current_node,
                                    'ingress_if': '---',
                                    'egress_if': f'{"TU-" + tunn_num}'
                                }
                            }
                            hop_list.append(new_vrouter)
                        else:
                            current_hop = 0
                            new_vrouter = {current_hop:
                                {
                                    'node': current_node,
                                    'ingress_if': 'Local',
                                    'egress_if': f'{"TU-"+tunn_num}'
                                }
                            }
                            hop_list.append(new_vrouter)
                    try:
                        next_ip = full_db[next_node]
                    except IndexError:
                        main_logger.error(f'Device {next_node} not found in JSON database')
                        exit(1)
                elif re.search(r'TenGi|Giga|BV', cef_hop_net):
                    end_ip = current_ip
                    end_node = current_node
                    if 'CS-PE' in current_node:
                        if len(hop_list) > 0:
                            current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                            if tunn_num != '':
                                ing_if = f'TU-{tunn_num}'
                            else:
                                ing_if = 'TU-IP'
                            new_vrouter = {current_hop:
                                {
                                    'node': current_node,
                                    'ingress_if': f'{ing_if}',
                                    'egress_if': f'{cef_hop_net}'
                                }
                            }
                            hop_list.append(new_vrouter)
                        else:
                            current_hop = 0
                            new_vrouter = {current_hop:
                                {
                                    'node': current_node,
                                    'ingress_if': f'{cef_hop_net}',
                                    'egress_if': f'{"TU-"+tunn_num}'
                                }
                            }
                            hop_list.append(new_vrouter)
                else:
                    main_logger.error(f'Unable to trace cef next_hop {cef_hop_net}, cef interface {cef_int}')
                    exit(1)
            current_node = next_node
            current_ip = next_ip
    return end_node, end_ip, hop_list


def printing_trace(hop_list: list) -> str:
    header = f'{"Hop":<5} {"Ingress IF":<20} {"Node":<15} {"Egress IF":<5}'
    columns = f'{"-" * 3:<5} {"-" * 10:<5} {"-" * 25:<5} {"-" * 10:<5}'
    hops = ''
    for hops in hop_list:
        for hop in hops:
            hop = f'{hop:<5} {hops[hop]["ingress_if"]:<10} {hops[hop]["node"]:>10} {hops[hop]["egress_if"]:<10}'
            hops = hops + hop + '\n'
    final_report = f'{header}\n{columns}\n{hops}'
    return final_report


def get_conn_int(node: str, vrf: str, full_db: dict):
    temp_ip = ''
    interface = ''
    if not check_ip(node):
        node = full_db[node]
    show_route = single_device_collection(node, f'show route vrf {vrf} local')
    main_logger.debug(f'GET CONNECTED IF:\n{"-"*30}\n{show_route}')
    for line in show_route.splitlines():
        if re.search(Regex.connected_route, line, re.M):
            interface = re.search(Regex.connected_route, line, re.M).group(2)
            if 'Loopback' not in interface:
                temp_ip = re.search(Regex.connected_route, line, re.M).group(1).split('/')[0]
                break
    main_logger.debug(f'\nGET CONNECTED IF - PARSED\n{"-"*30}\n Interface {interface} - IP {temp_ip}')
    return temp_ip


def isis_src(node: str, ip: str):
    show_isis_route = f'show isis route {ip} detail'
    isis_source = single_device_collection(node, show_isis_route)
    for lines in isis_source.splitlines():
        if re.search(Regex.isis_source, lines, re.M):
            node_name = re.search(Regex.isis_source, lines, re.M).group(1)
    return node_name


username = 'cisco_transport_sdn'
password = 'Ciscosdn!123'
socks_proxy = ('127.0.0.1', 8023)
if __name__ == '__main__':
    start_time = datetime.datetime.now()
    main_logger.info(f'Starting at {start_time}')
    with open('/Users/lrepetto/Documents/full_db.json', 'r') as file:
        full_db = json.load(file)
        file.close()
    with open('topo.json', 'r') as file_two:
        topo_dict = json.load(file_two)
        file.close()
    source = 'ATATLP0002A-CS000-PE001'
    vrf = '5GC-OAM'
    ip = '10.231.194.253'
    main_logger.info(f'Start Trace to ip {ip} at vrf {vrf}')
    result, rfp_result = run(source, ip, topo_dict, vrf=vrf)
    main_logger.warning('Trace finished')
    end_host, end_ip, hop_list = result
    rpf_host, rpf_ip, rpf_list = rfp_result
    first_path = printing_trace(hop_list)
    main_logger.info(f'\nTrace report {ip} at vrf {vrf}\n{"-"*30}\n{first_path}')
    rpf_path = printing_trace(rpf_list)
    main_logger.info(f'\nReversed Path\n{"-" * 30}\n{rpf_path}')
    end_time = datetime.datetime.now()
    main_logger.info(f'Finished execution. Took {(end_time - start_time)}')

