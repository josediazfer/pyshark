"""This module contains functions to turn TShark Follow Stream YAML parts into Packet objects."""
import yaml
import os

from pyshark.packet.packet_follow import PacketFollow
from pyshark.tshark.output_parser.base_parser import BaseTsharkOutputParser

class TsharkFollowStreamParser(BaseTsharkOutputParser):
    PEERS_BATCH_SIZE = 64

    def __init__(self):
        self._peers = None
        super().__init__()

    async def get_packets_from_stream(self, stream, existing_data, got_first_packet=True):
        try:
            packet, existing_data = await self._get_packets_from_stream(stream, existing_data, got_first_packet)
        except EOFError:
            # Try to get the last packet that it's remaining in the "existing_data" buffer??
            self._eof = True
            packet, existing_data = await self._get_packets_from_stream(None, existing_data, got_first_packet)

        return packet, existing_data


    async def _get_packets_from_stream(self, stream, existing_data, got_first_packet):
        if self._peers is None:
            existing_data = await self._get_peers_struct(stream, existing_data)

        return await super().get_packets_from_stream(stream, existing_data, got_first_packet=got_first_packet)

    async def _get_peers_struct(self, fd, existing_data):
        """Gets the "Follow Stream" header by reading the "peers" structure"""
        initial_data = existing_data
        peers_struct = None

        while not peers_struct:
            peers_struct, initial_data = _extract_field_from_yaml_data(initial_data, b"peers", b"packets", is_eof=self._eof)
            if peers_struct:
                self._peers = yaml.safe_load(peers_struct)
            elif not fd:
                break
            else:
                new_data = await fd.read(self.PEERS_BATCH_SIZE)
                if not new_data:
                    break
                initial_data += new_data

        return initial_data

    def _parse_single_packet(self, packet):
         packet_yaml = yaml.safe_load(packet)[0]
         src_peer = self._peers[packet_yaml["peer"]]
         dst_peer = self._peers[0 if packet_yaml["peer"] == 1 else 1]

         packet_yaml["src_host"] = src_peer["host"]
         packet_yaml["src_port"] = src_peer["port"]

         packet_yaml["dst_host"] = dst_peer["host"]
         packet_yaml["dst_port"] = dst_peer["port"]
         del packet_yaml["peer"]

         return PacketFollow(packet_yaml)


    def _extract_packet_from_data(self, data, got_first_packet=True):
        """Gets data containing a (part of) tshark follow stream yaml.

        Require before to get the peers headers structure otherwise returns None and the same data.
        If the given packet member is found in it, returns the packet member and the remaining data. 
        Otherwise returns None and the same data.
    
        :param data: string of a partial tshark follow stream yaml.
        :return: a tuple of (data_packet, data). data_packet will be None if none is found.
        """
        if self._peers is None:
            return None, existing_data

        data_packet, existing_data = _extract_field_from_yaml_data(data, field_name_start=b"packet", field_name_end=b"packet", is_member=True, is_eof=self._eof)

        return data_packet, existing_data

def _extract_field_from_yaml_data(data, field_name_start, field_name_end, is_member=False, is_eof=False):
    """Gets data containing a (part of) tshark follow stream yaml.

        If the given member or block is found in it, returns the data and the remaining data.
        Otherwise returns None and the same data.

        :param data: string of a partial tshark follow stream yaml.
        :param field_name_start: A bytes string that mark of the beginning of the member or block
        :param field_name_end: A bytes string that delimit the end of the member or block
        :param is_member: This is a member or a block
        :param is_eof: Reached end of file
        :return: a tuple of (member_block_data, data). member_block_data will be None if none is found.
    """
    prefix_field = b"  - " if is_member else b""
    suffix_field = b":" if is_member else bytes(f":{os.linesep}", "utf-8")
    start_pos = 0 if is_member else 0
    opening_field = prefix_field + field_name_start + suffix_field
    closing_field = prefix_field + field_name_end + suffix_field

    field_start = data.find(opening_field)
    if field_start == -1:
        return None, data

    if is_eof and is_member:
        return data[field_start:], data
    
    field_end = data.find(closing_field, field_start + len(opening_field))
    if field_end != -1:
        start_pos = 0 if is_member else len(opening_field)
        return data[(field_start + start_pos):field_end], data[field_end:]

    return None, data
