#!/usr/bin/env python3

import re
import json
import ipaddress
import datetime
import logging
import logging.handlers
import time
import os
import argparse
from sys import exit
from mtcollector import MTCollector
from ipaddress import AddressValueError

main_logger = logging.getLogger(__name__)
main_logger.setLevel(logging.INFO)
logger_handlers = logging.handlers.RotatingFileHandler(f'tracetopology.log', maxBytes=(1048576*5), backupCount=7)
logger_formatter = logging.Formatter('%(asctime)s,%(msecs)03d %(levelname)-3s [%(filename)s:%(lineno)d]-8s %(message)s')
logger_handlers.setFormatter(logger_formatter)
main_logger.addHandler(logger_handlers)


class Regex:
    rt_next_hop = r'^\s+(\d+.\d+.\d+.\d+),.*$'
    rt_entry = r'^Routing entry for (\S+)$'
    nhop_interface = r'^\s+\S+\s+connected,\s+via\s+(\S+)$'
    tip_desc = r''
    cef_vrf_subnet = r'^(\d+.\d+.\d+.\d+/\d+),\sversion.*$'
    cef_nhop = r'^\s+via\s(BVI\d+|\d+.\d+.\d+.\d+/\d+|TenGigE\S+|Giga\S+|Loopback\d+),.*$'
    cef_int_nhop = r'^\s+\d+\s+\S+\s+(\S+)\s+(\S+)\s+$'
    tunnel_desc = r'^.*To\s+(\S+):Tunnel-ip\d+$'
    connected_route = r'^^L\s+(\S+)\sis directly connected, \S+\s+(\S+)$'
    isis_source = r'^\s+src\s+(\S+)\.\S+,.*$'
    isis_instance = r'^IS-IS\s(\S+)\spaths.*$'
    show_cef_addr = r'^show cef vrf \S+ (\S+) detail'


class IsisTopologyDB:
    def __init__(self):
        self.pe_dict = None
        self.topology_dict = {}
        self.db_wd = f'{os.getcwd()}/database'
        self.file = None
        self._load_from_file()

    def set_pe_dict(self, pe_dict: dict) -> None:
        self.pe_dict = pe_dict

    def get_topology(self) -> dict:
        if not self.topology_dict:
            self._first_time()
        return self.topology_dict

    def update_site(self, site: str) -> None:
        if site in self.pe_dict:
            self._gather_topology(target_device=site)
            if self.file is None:
                main_logger.error(f'Topology DB not loaded, after this run site will remain out of date')
            else:
                self._update_file(self.file)
        else:
            main_logger.error(f'Site {site} not found in PE Database, please update the source before retry')
            exit(1)

    def update_topology(self, force: bool = False):
        if force is True:
            self._first_time()
        else:
            self._gather_topology()

    def _update_file(self, file: str) -> None:
        with open(file, 'w') as topology_file:
            topology_file.truncate(0)
            topology_file.close()
        with open(file, 'w') as topology_file:
            json.dump(self.topology_dict, topology_file, indent=4)
            topology_file.close()

    def _gather_topology(self, target_device: str = None) -> None:
        global mtcollector_opts
        if 'socks_proxy' in mtcollector_opts:
            mtcollector_opts['maxthreads'] = 3
        show_topology = 'show isis topology'
        main_logger.info(f"Gathering ISIS topology - if it's a full discovery could take some time")
        start_isis_time = datetime.datetime.now()
        main_logger.debug(f'Start time: {start_isis_time}')
        if not target_device:
            output_isis = MTCollector(self.pe_dict, show_topology, **mtcollector_opts)
            if 'not_connected' in output_isis:
                main_logger.debug(f'\nDevices not connected\n{"-"*30}\n{output_isis["not_connected"]}')
            for device in output_isis:
                if device != 'not_connected':
                    self._topology_population(self.topology_dict, output_isis[device][0][show_topology])
                else:
                    for not_connected in output_isis[device]:
                        main_logger.debug(f'\n"NOT_CONNECTED" OUTPUT COLLECTION\n{"-" * 30}')
                        if not_connected in self.pe_dict:
                            mgmt_ip = self.pe_dict[not_connected]
                            single_ouptut = single_device_collection(mgmt_ip, show_topology)
                            if single_ouptut:
                                self._topology_population(self.topology_dict, single_ouptut)
                            else:
                                main_logger.error(f'WARNING: Topology incomplete, unable to reach {not_connected}')
                        else:
                            main_logger.error(f'WARNING: Topology incomplete, {device} not found in IP DB')
        else:
            if target_device in self.pe_dict:
                mgmt_ip = self.pe_dict[target_device]
                single_ouptut = single_device_collection(mgmt_ip, show_topology)
                main_logger.debug(f'\nTARGETED OUTPUT COLLECTION\n{"-" * 30}')
                main_logger.debug(f'\noutput {show_topology} for {target_device}:\n{"-" * 30}\n{single_ouptut}\n\n')
                try:
                    self._topology_population(self.topology_dict, single_ouptut)
                except TypeError:
                    main_logger.error(f'WARNING: Topology incomplete, unable to reach {target_device}')
        end_isis_time = datetime.datetime.now()
        main_logger.debug(f'Isis collection lasted: {(end_isis_time - start_isis_time).total_seconds()}')

    def _topology_population(self, topology_dict: dict, output: str) -> None:
        system = self._get_system(output)
        main_logger.debug(f'Starting Topology Population for system {system}')
        if system not in topology_dict:
            main_logger.debug(f'System not detected in current topology, creating base data structure')
            topology_dict[system] = {'edges': {}, 'nhsystems': {}}
        output_lines = output.splitlines()
        index = 2
        while True:
            if len(output_lines) <= index:
                break
            else:
                line = output_lines[index]
                if re.search(Regex.isis_instance, line, re.M):
                    if 'ACCESS' in re.search(Regex.isis_instance, line, re.M).group(1):
                        main_logger.debug(f'ISIS ACCESS instance detected, finishing the topology population')
                        break
                    else:
                        index += 1
                elif 'System Id' in line or line == '':
                    index += 1
                else:
                    split_line = line.split()
                    if len(split_line) > 2:
                        if split_line[0] == split_line[2]:
                            main_logger.debug(f'EDGE DETECTED - {split_line[0]}')
                            self._new_edge(topology_dict[system]['edges'], split_line)
                        else:
                            self._nhop_system(topology_dict[system]['nhsystems'], split_line)
                    index += 1

    def _load_from_file(self):
        topology_file_list = [os.path.join(self.db_wd, f) for f in os.listdir(self.db_wd) if 'topology' in f]
        if len(topology_file_list) > 0:
            if self._check_if_update(topology_file_list[0]):
                main_logger.warning(f'File is older than 6hs, if you want to update the file set force to true')
            with open(topology_file_list[0], 'r') as topology_file:
                main_logger.debug(f'ISIS topology file detected: {topology_file_list[0]}')
                self.file = topology_file_list[0]
                self.topology_dict = json.load(topology_file)

    def _first_time(self):
        main_logger.info(f'ISIS topology file not detected or force set to True! '
                         f'running a first time full topology query')
        self.topology_dict = {}  # clear topology dict
        self._gather_topology()
        main_logger.info(f'ISIS Topology captured, saving to file...')
        if self.topology_dict:
            with open(f'{self.db_wd}/topology_database.json', 'w') as topology_file:
                self.file = topology_file
                json.dump(self.topology_dict, topology_file, indent=4)
                topology_file.close()

    @staticmethod
    def _check_if_update(file: str, hours: int = 6) -> bool:
        file_timestamp = os.path.getmtime(file)
        file_timestamp_delta = datetime.datetime.fromtimestamp(file_timestamp)
        delta = datetime.datetime.now() - file_timestamp_delta
        main_logger.debug(f'File timestamp {file_timestamp_delta}, Current time: {datetime.datetime.now()}, '
                          f'Delta: {delta}')
        if (delta / datetime.timedelta(hours=1)) > hours:
            return True
        else:
            return False

    @staticmethod
    def _new_edge(system_dict: dict, output_line: list) -> None:
        edge = output_line[2]
        interface = output_line[3]
        metric = output_line[1]
        if edge not in system_dict:
            system_dict[edge] = {'nhi': interface, 'metric': metric}

    @staticmethod
    def _nhop_system(system_dict: dict, output_line: list) -> None:
        nh_systemp = output_line[0]
        metric = output_line[1]
        edge = output_line[2]
        if nh_systemp not in system_dict:
            system_dict[nh_systemp] = []
        system_dict[nh_systemp].append((edge, metric))

    @staticmethod
    def _get_system(output: str) -> str:
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
        elif 'AR' in current_node.split('-')[2]:
            start_node = ''
            for nodes in topo_dict:
                if current_node in topo_dict[nodes]['edges']:
                    start_node = nodes
                    break
            if start_node == '':
                main_logger.error(f'Unable to find {current_node} connected to any edges')
            else:
                if current_node in topo_dict[start_node]['edges']:
                    nhi = topo_dict[start_node]['edges'][current_node]['nhi']
                    hop_dict = {hop: {'node': current_node, 'egress_if': nhi, 'ingress_if': '---'}}
                    hop_list.append(hop_dict)
                current_node = start_node
                hop += 1
                continue
        else:
            if current_node in topo_dict:
                if dest in topo_dict[current_node]['nhsystems']:    
                    edge = topo_dict[current_node]['nhsystems'][dest][0][0]
                    nhi = topo_dict[current_node]['edges'][edge]['nhi']
                    main_logger.debug(f'Current node: {current_node}, Edge: {edge}, Previous node: {previous_node}')
                    if hop > 0:
                        if previous_node in topo_dict[current_node]['edges']:
                            ing_if = topo_dict[current_node]['edges'][previous_node]['nhi']
                        else:
                            main_logger.error(f'Previous node: {previous_node} not in {current_node} edges DB, '
                                              f'setting Ingress interface to blank')
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
                    if previous_node in topo_dict[current_node]['edges']:
                        ing_if = topo_dict[current_node]['edges'][previous_node]['nhi']
                    else:
                        main_logger.error(f'Previous node: {previous_node} not in {current_node} edges DB, '
                                          f'setting Ingress interface to blank')
                        ing_if = ''
                    hop_dict = {hop: {'node': current_node, 'egress_if': nhi, 'ingress_if': ing_if}}
                    if 'AR' not in dest.split('-')[2]:
                        ing_ifz = topo_dict[dest]['edges'][current_node]['nhi']
                    else:
                        ing_ifz = nhi
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
                      f''f'NHOP: {nhop_ip}, NHOP INT: {nhop_int}, NHOP ADDR: {nhop_addr}')
    if '0.0.0.0' in subnet:
        if '/32' in subnet and 'null0' in nhop_addr:
            return 'null0', 'no-hop'
        else:
            return 'default', 'no-nhop'
    else:
        return nhop_ip, nhop_int, nhop_addr


def first_hop(output: str) -> str:
    hop = ''
    for lines in output.splitlines():
        no_newline_output = lines.split()
        if len(no_newline_output) > 2:
            if no_newline_output[0] == no_newline_output[2]:
                hop = no_newline_output[0]
                break
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
    global mtcollector_opts
    packed_output = MTCollector(node_ip, show, **mtcollector_opts)
    if 'not_connected' in packed_output:
        main_logger.error(f'Unable to connect to device {node_ip}')
        exit(1)
    else:
        unpacked_output = packed_output[node_ip][0][show]
        return unpacked_output


def run(start_node: str, ip: str, topo_dict: dict, source_ip: str = None, vrf: str = None) -> tuple:

    if source_ip is None:
        source_ip = get_conn_int(start_node, vrf, full_db)
    if check_ip(start_node):
        start_node_ip = start_node
        start_node = [node for node, ip in full_db.items() if ip == start_node_ip]
        if start_node:
            start_node = start_node[0]
        else:
            main_logger.error(f'Node IP {start_node_ip} not found on the DB, is the right ip?')
            exit(1)
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
    global full_db
    chy_routers = ['che1r00001-ne-pe01', 'CYSWY0001N-CS247-AGG003', 'CYSWY0001N-CS248-AGG004', 'che1r00001-ne-pe02']
    hop_list = []
    current_node = start_node
    current_ip = [ip for sys, ip in full_db.items() if start_node == sys][0]
    end_node = ''
    end_ip = ''
    main_logger.info(f'Starting Full Trace - start node: {start_node}')
    tunn_num = ''
    while True:
        if 'SERVICE-MGMT' in show_cef and current_node in chy_routers:
            show_cef_mod = show_cef.replace('SERVICE-MGMT', 'MGMT')
            cef_output = single_device_collection(current_ip, show_cef_mod)
        else:
            cef_output = single_device_collection(current_ip, show_cef)
        main_logger.debug(f'CEF OUTPUT - {current_node}\n{"-" * 30}\n{cef_output}\n\n')
        cef_hop_net, cef_int, cef_addr = cef_nhop(cef_output)
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
                    if check_ip(cef_addr):  # cef pointing to recursive
                        current_cef_ip = re.search(Regex.show_cef_addr, show_cef, re.M).group(1)
                        show_cef_recursive = show_cef.replace(current_cef_ip, cef_addr)
                        cef_output = single_device_collection(current_ip, show_cef_recursive)
                        cef_hop_net, cef_int, cef_addr = cef_nhop(cef_output)
                        show_desc = f'show interface {cef_int} | i Description'
                        tunnel_descrip = single_device_collection(current_ip, show_desc)
                        next_node = tunnel_description(tunnel_descrip)
                        tunn_num = cef_int.split('ip')[1]
                        main_logger.debug(
                            f'---- NHOP Tunnel detected ---\nOutput\n{"-" * 30}\n{tunnel_descrip}\n'
                            f'Parsed\n{"-" * 30}\nNext Node: {next_node}, Tunnel Number: {tunn_num} '
                        )
                        if 'CS-PE' in next_node:
                            if len(hop_list) > 0:
                                current_hop = [x for x, y in hop_list[-1].items()][0]
                                if current_node == hop_list[-1][current_hop]['node']:
                                    hop_list[-1][current_hop]['egress_if'] = f'{"TU-" + tunn_num}'
                            else:
                                current_hop = 0
                                new_vrouter = {current_hop: {'node': current_node,
                                                             'ingress_if': 'Local',
                                                             'egress_if': f'{"TU-" + tunn_num}'
                                                             }
                                               }
                                hop_list.append(new_vrouter)
                        else:
                            if len(hop_list) > 0:
                                current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                                new_vrouter = {current_hop: {'node': current_node,
                                                             'ingress_if': '---',
                                                             'egress_if': f'{"TU-" + tunn_num}'
                                                             }
                                               }
                                hop_list.append(new_vrouter)
                            else:
                                current_hop = 0
                                new_vrouter = {current_hop: {'node': current_node,
                                                             'ingress_if': 'Local',
                                                             'egress_if': f'{"TU-" + tunn_num}'
                                                             }
                                               }
                                hop_list.append(new_vrouter)
                        try:
                            next_ip = full_db[next_node]
                        except IndexError:
                            main_logger.error(f'Device {next_node} not found in JSON database')
                            exit(1)
                    elif check_ip(cef_hop_net):
                        if 'CSR' in current_node:
                            isis_hop_ip = full_db[isis_hop]
                            next_node = isis_src(isis_hop_ip, cef_hop_net)
                            next_ip = full_db[next_node]
                            if len(hop_list) > 0:
                                current_hop = [x for x, y in hop_list[-1].items()][0]
                                next_hop = current_hop + 1
                                temp_list = isis_topology_trace(topo_dict, isis_hop, next_node, hop=next_hop)
                                if temp_list[0][next_hop]['node'] == hop_list[-1][current_hop]['node']:
                                    hop_list[-1][current_hop]['egress_if'] = temp_list[0][next_hop]['egress_if']
                                    temp_list.pop(0)
                                    shifted_temp = []
                                    for values in temp_list:
                                        for hops in values:
                                            new_hop = {hops - 1: values[hops]}
                                            shifted_temp.append(new_hop)
                                hop_list = hop_list + shifted_temp
                            else:
                                hop_list = isis_topology_trace(topo_dict, isis_hop, next_node)
                        elif 'CS-PE' in current_node:
                            next_node = isis_src(current_ip, cef_hop_net)
                            next_ip = full_db[next_node]
                            if len(hop_list) > 0:
                                current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                                new_vrouter = {current_hop: {'node': current_node,
                                                             'ingress_if': 'TU-IP',
                                                             'egress_if': 'TU-IP'
                                                             }
                                               }
                                hop_list.append(new_vrouter)
                            else:
                                current_hop = 0
                                new_vrouter = {current_hop: {'node': current_node,
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
                                current_hop = [x for x, y in hop_list[-1].items()][0]
                                next_hop = current_hop + 1
                                temp_list = isis_topology_trace(topo_dict, current_node, next_node, hop=next_hop)
                                if temp_list[0][next_hop]['node'] == hop_list[-1][current_hop]['node']:
                                    hop_list[-1][current_hop]['egress_if'] = temp_list[0][next_hop]['egress_if']
                                    temp_list.pop(0)
                                    shifted_temp = []
                                    for values in temp_list:
                                        for hops in values:
                                            new_hop = {hops - 1: values[hops]}
                                            shifted_temp.append(new_hop)
                                hop_list = hop_list + shifted_temp
                            else:
                                hop_list = isis_topology_trace(topo_dict, current_node, next_node)
                            if next_node == isis_hop:
                                end_node = next_node
                                end_ip = next_ip
                    elif re.search(r'TenGi|Giga|BV|Loopback', cef_hop_net):
                        end_ip = current_ip
                        end_node = current_node
                        if len(hop_list) > 0:
                            current_hop = [x for x, y in hop_list[-1].items()][0]
                            if hop_list[-1][current_hop]['node'] == current_node:
                                hop_list[-1][current_hop]['egress_if'] = f'{cef_hop_net}'
                            else:
                                new_vrouter = {current_hop: {'node': current_node,
                                                             'ingress_if': 'TU-IP',
                                                             'egress_if': f'{cef_int}'
                                                             }
                                               }
                                hop_list.append(new_vrouter)
                        else:
                            current_hop = 0
                            new_vrouter = {current_hop: {'node': current_node,
                                                         'ingress_if': '---',
                                                         'egress_if': 'TU-IP'
                                                         }
                                           }
                            hop_list.append(new_vrouter)
                    else:
                        main_logger.error(f'Unable to trace cef next_hop {cef_hop_net}, cef interface {cef_int}')
                        exit(1)
                elif 'tunnel' in cef_int:
                    show_desc = f'show interface {cef_int} | i Description'
                    tunnel_descrip = single_device_collection(current_ip, show_desc)
                    next_node = tunnel_description(tunnel_descrip)
                    tunn_num = cef_int.split('ip')[1]
                    main_logger.debug(
                        f'---- NHOP Tunnel detected ---\nOutput\n{"-"*30}\n{tunnel_descrip}\n'
                        f'Parsed\n{"-"*30}\nNext Node: {next_node}, Tunnel Number: {tunn_num} '
                    )
                    if 'CS-PE' in next_node:
                        if len(hop_list) > 0:
                            current_hop = [x for x, y in hop_list[-1].items()][0]
                            if current_node == hop_list[-1][current_hop]['node']:
                                hop_list[-1][current_hop]['egress_if'] = f'{"TU-"+tunn_num}'
                    else:
                        if len(hop_list) > 0:
                            current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                            new_vrouter = {current_hop: {'node': current_node,
                                                         'ingress_if': '---',
                                                         'egress_if': f'{"TU-" + tunn_num}'
                                                         }
                                           }
                            hop_list.append(new_vrouter)
                        else:
                            current_hop = 0
                            new_vrouter = {current_hop: {'node': current_node,
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
                elif re.search(r'TenGi|Giga|BV|Loopback', cef_int):
                    end_ip = current_ip
                    end_node = current_node
                    if 'CS-PE' in current_node:
                        if len(hop_list) > 0:
                            current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                            if tunn_num != '':
                                ing_if = f'TU-{tunn_num}'
                            else:
                                ing_if = 'TU-IP'
                            new_vrouter = {current_hop: {'node': current_node,
                                                         'ingress_if': f'{ing_if}',
                                                         'egress_if': f'{cef_hop_net}'
                                                         }
                                           }
                            hop_list.append(new_vrouter)
                        else:
                            current_hop = 0
                            new_vrouter = {current_hop: {'node': current_node,
                                                         'ingress_if': f'{cef_hop_net}',
                                                         'egress_if': f'{"TU-"+tunn_num}'
                                                         }
                                           }
                            hop_list.append(new_vrouter)
                    else:
                        if len(hop_list) > 0:
                            current_hop = [x for x, y in hop_list[-1].items()][0] + 1
                            if hop_list[-1][current_hop]['node'] == current_node:
                                hop_list[-1][current_hop]['egress_if'] = f'{cef_int}'
                            else:
                                new_vrouter = {current_hop: {'node': current_node,
                                                             'ingress_if': '---',
                                                             'egress_if': f'{"TU-" + tunn_num}'
                                                             }
                                               }
                                hop_list.append(new_vrouter)
                        else:
                            current_hop = 0
                            new_vrouter = {current_hop: {'node': current_node,
                                                         'ingress_if': f'{cef_int}',
                                                         'egress_if': f'{"TU-" + tunn_num}'
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
    hops_print = ''
    for hops in hop_list:
        for hop in hops:
            hop = f'{hop:<5} {hops[hop]["ingress_if"]:<10} {hops[hop]["node"]:>10} {hops[hop]["egress_if"]:<10}'
            hops_print = hops_print + hop + '\n'
    final_report = f'{header}\n{columns}\n{hops_print}'
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


def print_banner():
    print("""
     _____                _____                 _                   
    |_   _|              |_   _|               | |                  
      | |_ __ __ _  ___ ___| | ___  _ __   ___ | | ___   __ _ _   _ 
      | | '__/ _` |/ __/ _ \ |/ _ \| '_ \ / _ \| |/ _ \ / _` | | | |
      | | | | (_| | (_|  __/ | (_) | |_) | (_) | | (_) | (_| | |_| |
      \_/_|  \__,_|\___\___\_/\___/| .__/ \___/|_|\___/ \__, |\__, |
                                   | |                   __/ | __/ |
                                   |_|                  |___/ |___/ 
        
        By L. Repetto - leanrepetto@gmail.com                           
        \n""")


def main_menu(topology: IsisTopologyDB):
    os.system('clear')
    cwd = os.getcwd()
    print_banner()
    while True:
        print('\tSelect from the menu:\n\n'
              '\t\t1) Force ISIS Topology update\n'
              '\t\t2) Trace IP address\n\n')
        try:
            selection = int(input('\t\tSelection: '))
            if selection == 1:
                topology.update_topology(force=True)
            elif selection == 2:
                ip_to_trace, vrf, node = trace_ip_menu()

                topo_dict = topology.get_topology()
                trace, rpf_trace = run(node, ip_to_trace, topo_dict, vrf=vrf)
                end_host, end_ip, hop_list = trace
                rpf_host, rpf_ip, rpf_hop_list = rpf_trace
                os.system('clear')
                final_report = printing_trace(hop_list)
                rpf_final_report = printing_trace(rpf_hop_list)
                print(f'{final_report}\nReversed Path\n{rpf_final_report}')
                filename = node + '-' + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                with open(f'{cwd}/tracelogs/{filename}.log', 'w') as file:
                    print(f'\n\nSaving results to {filename}')
                    file.write(f'{final_report}\nReversed Path\n{rpf_final_report}')
                break
            else:
                print('\n\tWrong number, please select again\n')
                time.sleep(2)
                continue
        except ValueError:
            print('\n\tThat\'s not a valid option\n')
            time.sleep(2)
    print('Thank you for using TraceTopology! any feedback is more than wellcome!')


def trace_ip_menu():
    while True:
        trace_ip = input('\nIP to Trace: ')
        if check_ip(trace_ip):
            break
        else:
            print('\nInput is not a valid IP address')
            continue
    vrf = input('\nVRF: ').upper()
    source_node = input('\nStart Node: ').upper()
    return trace_ip, vrf, source_node


def arguments():
    parser = argparse.ArgumentParser(prog='tracetopology', description='Trace IP address over SR-MPLS network')
    req_argument = parser.add_argument_group('Required Argument:')
    opt_argument = parser.add_argument_group('Optinal Arguments:')
    req_argument.add_argument('-i', '--ipaddress', help='IP Address to trace')
    req_argument.add_argument('-n', '--node', help='Node name or IP to start trace from')
    opt_argument.add_argument('-v', '--vrf', help='VRF on which the trace must happen. Default = None')
    #  opt_argument.add_argument('--gui', help='Run the guided menu') for future support
    opt_argument.add_argument('--loglevel', help='Set the log level ')
    opt_argument.add_argument('--socks', help='Sets socks (ip:port) proxy. Default = None')
    req_argument.add_argument('-u', '--username', help='set username')
    req_argument.add_argument('-p', '--password', help='set password')
    opt_argument.add_argument('--generate_topology', help='Create/update ISIS topology', action='store_true')
    opt_argument.add_argument('--update_node', help='Update ISIS topology for a given --node', action='store_true')
    return parser.parse_args()


def main(pe_dict: dict):
    global mtcollector_opts
    set_arguments = arguments()
    if set_arguments.loglevel:
        log_level = logging.getLevelName(set_arguments.loglevel.upper())
        main_logger.setLevel(log_level)
    if not set_arguments.username or not set_arguments.password:
        main_logger.error('Username (-u) and Password (-p) are mantadory! ')
        exit(1)
    if not set_arguments.node:
        main_logger.error('Missing startig node (-n)')
        exit(1)
    mtcollector_opts['user'] = set_arguments.username
    mtcollector_opts['paswd'] = set_arguments.password
    topology = IsisTopologyDB()
    topology.set_pe_dict(pe_dict)
    if set_arguments.generate_topology:
        topology.update_topology(force=True)
    elif set_arguments.update_node:
        topology.update_site(set_arguments.node)
    else:
        if not set_arguments.ipaddress:
            main_logger.error('Missing IP Address (-i) to trace!')
            exit(1)
        if set_arguments.socks:
            ip = set_arguments.socks.split(':')[0]
            port = int(set_arguments.socks.split(':')[1])
            mtcollector_opts['socks_proxy'] = (ip, port)
        isis_topology_dict = topology.get_topology()
        ip_to_trace = set_arguments.ipaddress
        node = set_arguments.node
        if set_arguments.vrf:
            trace, rpf_trace = run(node, ip_to_trace, isis_topology_dict, vrf=set_arguments.vrf)
        else:
            trace, rpf_trace = run(node, ip_to_trace, isis_topology_dict)
        end_host, end_ip, hop_list = trace
        rpf_host, rpf_ip, rpf_hop_list = rpf_trace
        os.system('clear')
        final_report = printing_trace(hop_list)
        rpf_final_report = printing_trace(rpf_hop_list)
        print(f'{final_report}\nReversed Path\n{rpf_final_report}')
        filename = node + '-' + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        with open(f'{cwd}/tracelogs/{filename}.log', 'w') as file:
            print(f'\n\nSaving results to {filename}')
            file.write(f'{final_report}\nReversed Path\n{rpf_final_report}')


mtcollector_opts = {
    'user': '',
    'paswd': ''
}
if __name__ == '__main__':
    cwd = os.getcwd()
    start_time = datetime.datetime.now()
    main_logger.info(f'Starting at {start_time}')
    print_banner()
    with open(f'{cwd}/database/full_db.json', 'r') as file:
        full_db = json.load(file)
        file.close()
    with open(f'{cwd}/database/dish_pes.json') as pe_file:
        pe_dict = json.load(pe_file)
        pe_file.close()
    main(pe_dict)
    end_time = datetime.datetime.now()
    main_logger.info(f'Ending at {start_time}')
    main_logger.info(f'job lasted for: {(end_time - start_time).total_seconds()}')
    print('Thank you for using TraceTopology! any feedback is more than wellcome!')

