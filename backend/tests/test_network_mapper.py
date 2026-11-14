from __future__ import annotations
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
import network_mapper
from network_mapper import PuyadNetworkMapper, _is_private, _parse_ss_output, _split_host_port

class TestNetworkMapper:

    def test_is_private(self):
        assert _is_private('127.0.0.1') is True
        assert _is_private('10.0.0.5') is True
        assert _is_private('172.16.1.1') is True
        assert _is_private('172.31.255.255') is True
        assert _is_private('192.168.1.100') is True
        assert _is_private('169.254.10.20') is True
        assert _is_private('0.0.0.0') is True
        assert _is_private('::1') is True
        assert _is_private('fe80::1') is True
        assert _is_private('::ffff:127.0.0.1') is True
        assert _is_private('') is True
        assert _is_private('invalid.ip') is True
        assert _is_private('8.8.8.8') is False
        assert _is_private('1.1.1.1') is False
        assert _is_private('104.26.10.1') is False

    def test_split_host_port(self):
        assert _split_host_port('127.0.0.1:8080') == ('127.0.0.1', '8080')
        assert _split_host_port('[::1]:443') == ('::1', '443')
        assert _split_host_port('*:22') == ('0.0.0.0', '22')
        assert _split_host_port('0.0.0.0:*') == ('0.0.0.0', '')
        assert _split_host_port('') == ('', '')
        assert _split_host_port('*') == ('', '')
        assert _split_host_port('[fe80::1%eth0]:546') == ('fe80::1', '546')

    def test_parse_ss_output(self):
        raw_ss = 'Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess\ntcp   LISTEN 0      128    0.0.0.0:8000        0.0.0.0:*    users:(("python3",pid=1234,fd=5))\ntcp   ESTAB  0      0      127.0.0.1:8000      127.0.0.1:45678 users:(("python3",pid=1234,fd=6))\n'
        conns = _parse_ss_output(raw_ss)
        assert len(conns) == 2
        listen = conns[0]
        assert listen['proto'] == 'tcp'
        assert listen['state'] == 'LISTEN'
        assert listen['local_ip'] == '0.0.0.0'
        assert listen['local_port'] == '8000'
        assert listen['process'] == 'python3'
        estab = conns[1]
        assert estab['state'] == 'ESTAB'
        assert estab['local_port'] == '8000'
        assert estab['peer_ip'] == '127.0.0.1'
        assert estab['peer_port'] == '45678'

    def test_geoip_private_ip(self):
        res = PuyadNetworkMapper.get_geoip_data('192.168.1.1')
        assert res['is_private'] is True
        assert res['country'] == 'Yerel'

    @patch('httpx.get')
    def test_geoip_public_ip_fetch_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'status': 'success', 'country': 'Germany', 'countryCode': 'DE', 'city': 'Frankfurt', 'lat': 50.1109, 'lon': 8.6821, 'org': 'Example Org', 'isp': 'Example ISP'}
        mock_get.return_value = mock_resp
        ip = '93.184.216.34'
        network_mapper._geoip_cache.pop(ip, None)
        res = PuyadNetworkMapper.get_geoip_data(ip)
        assert res['country'] == 'Germany'
        assert res['city'] == 'Frankfurt'
        assert res['lat'] == 50.1109
        assert res['is_private'] is False
        assert ip in network_mapper._geoip_cache

    @patch('network_mapper._run')
    def test_get_active_connections_map(self, mock_run):
        mock_run.return_value = 'Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess\ntcp   LISTEN 0      128    0.0.0.0:8000        0.0.0.0:*    users:(("uvicorn",pid=100,fd=3))\ntcp   ESTAB  0      0      127.0.0.1:8000      192.168.1.50:54321\n'
        with patch('compat.IS_LINUX', True):
            res = PuyadNetworkMapper.get_active_connections_map()
            assert 'nodes' in res
            assert 'edges' in res
            assert res['total_connections'] == 2
            node_ids = [n['id'] for n in res['nodes']]
            assert 'server' in node_ids
            assert 'port_8000' in node_ids
            assert 'client_192.168.1.50' in node_ids
