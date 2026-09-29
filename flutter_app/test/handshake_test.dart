import 'package:flutter_test/flutter_test.dart';
import 'package:bettercap_wifi/api_client.dart';

void main() {
  test('parses /api/handshakes records and classifies kind', () {
    final full = HandshakeInfo.fromJson({
      'ap_bssid': 'aa:bb:cc:dd:ee:ff',
      'ap_essid': 'CorpNet',
      'channel': 6,
      'encryption': 'WPA2',
      'ap_key_material': true,
      'station': '11:22:33:44:55:66',
      'station_vendor': 'Acme',
      'pmkid': false,
      'half': true,
      'complete': true,
      'unsaved': 2,
    });
    expect(full.kind, 'FULL');
    expect(full.strength, 2);
    expect(full.apName, 'CorpNet');
    expect(full.key, 'aa:bb:cc:dd:ee:ff|11:22:33:44:55:66');

    final pmkid = HandshakeInfo.fromJson({
      'ap_bssid': 'aa:bb:cc:dd:ee:00',
      'ap_essid': '',
      'pmkid': true,
      'half': false,
      'complete': false,
      'station': '',
    });
    expect(pmkid.kind, 'PMKID');
    expect(pmkid.strength, 3);
    expect(pmkid.apHidden, true); // empty essid renders as hidden
  });
}
