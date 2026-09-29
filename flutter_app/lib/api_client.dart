import 'dart:convert';
import 'dart:io';

/// Thin client for the bettercap-wifi HTTP API.
///
/// Every mutation goes through POST /api/session {"cmd": "..."} — the same
/// command dispatcher used by the interactive prompt on the backend.
class ApiClient {
  String baseUrl;
  String token;

  ApiClient({this.baseUrl = 'http://127.0.0.1:8081', this.token = ''});

  final HttpClient _http = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5);

  Future<dynamic> _request(String method, String path, {Object? body}) async {
    final uri = Uri.parse('$baseUrl$path');
    final req = await _http.openUrl(method, uri);
    req.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (token.isNotEmpty) req.headers.set('X-Api-Token', token);
    if (body != null) {
      req.headers.contentType = ContentType.json;
      req.write(jsonEncode(body));
    }
    final resp = await req.close();
    final text = await resp.transform(utf8.decoder).join();
    final decoded = text.isEmpty ? null : jsonDecode(text);
    if (resp.statusCode >= 400) {
      final msg = (decoded is Map && decoded['error'] != null)
          ? decoded['error'].toString()
          : 'HTTP ${resp.statusCode}';
      throw ApiException(msg, resp.statusCode);
    }
    return decoded;
  }

  Future<SessionInfo> getSession() async {
    final json = await _request('GET', '/api/session') as Map<String, dynamic>;
    return SessionInfo.fromJson(json);
  }

  Future<List<AccessPoint>> getWifi() async {
    final json = await _request('GET', '/api/wifi') as Map<String, dynamic>;
    return _apsFrom(json);
  }

  Future<List<ApEvent>> getEvents({int n = 100}) async {
    final json = await _request('GET', '/api/events?n=$n') as List<dynamic>;
    return json
        .map((e) => ApEvent.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Future<Map<String, String>> getEnv() async {
    final json = await _request('GET', '/api/env') as Map<String, dynamic>;
    return json.map((k, v) => MapEntry(k, v.toString()));
  }

  /// Runs a raw command, e.g. `wifi.recon on` or `wifi.deauth aa:bb:...`.
  Future<void> run(String command) async {
    await _request('POST', '/api/session', body: {'cmd': command});
  }

  Future<void> clearEvents() => _request('DELETE', '/api/events');

  /// Captured handshakes, derived from the live WiFi state on the backend
  /// (durable — independent of the transient event stream).
  Future<HandshakesResult> getHandshakes() async {
    final json = await _request('GET', '/api/handshakes') as Map<String, dynamic>;
    final items = (json['handshakes'] as List<dynamic>? ?? const [])
        .whereType<Map<String, dynamic>>()
        .map(HandshakeInfo.fromJson)
        .toList();
    return HandshakesResult(
      file: json['file']?.toString() ?? '',
      items: items,
    );
  }

  /// Downloads the captured-handshakes pcap to [savePath]. Returns the number
  /// of bytes written.
  Future<int> downloadPcap(String savePath) async {
    final uri = Uri.parse('$baseUrl/api/handshakes/pcap');
    final req = await _http.getUrl(uri);
    req.headers.set(HttpHeaders.acceptHeader, 'application/octet-stream');
    if (token.isNotEmpty) req.headers.set('X-Api-Token', token);
    final resp = await req.close();

    if (resp.statusCode >= 400) {
      final text = await resp.transform(utf8.decoder).join();
      var msg = 'HTTP ${resp.statusCode}';
      try {
        final d = jsonDecode(text);
        if (d is Map && d['error'] != null) msg = d['error'].toString();
      } catch (_) {}
      throw ApiException(msg, resp.statusCode);
    }

    final bytes = <int>[];
    await for (final chunk in resp) {
      bytes.addAll(chunk);
    }
    await File(savePath).writeAsBytes(bytes);
    return bytes.length;
  }

  void close() => _http.close(force: true);
}

class ApiException implements Exception {
  final String message;
  final int statusCode;
  ApiException(this.message, this.statusCode);
  @override
  String toString() => message;
}

List<AccessPoint> _apsFrom(Map<String, dynamic> wifiJson) {
  final aps = (wifiJson['aps'] as List<dynamic>?) ?? const [];
  return aps
      .whereType<Map<String, dynamic>>()
      .map(AccessPoint.fromJson)
      .toList();
}

class SessionInfo {
  final String name;
  final String version;
  final String os;
  final bool injectionSupported;
  final bool active;
  final List<ModuleInfo> modules;
  final List<AccessPoint> accessPoints;

  SessionInfo({
    required this.name,
    required this.version,
    required this.os,
    required this.injectionSupported,
    required this.active,
    required this.modules,
    required this.accessPoints,
  });

  ModuleInfo? get wifiModule =>
      modules.where((m) => m.name == 'wifi').cast<ModuleInfo?>().firstOrNull;

  bool get reconRunning => wifiModule?.running ?? false;

  factory SessionInfo.fromJson(Map<String, dynamic> j) {
    final mods = (j['modules'] as List<dynamic>? ?? const [])
        .whereType<Map<String, dynamic>>()
        .map(ModuleInfo.fromJson)
        .toList();
    final wifi = j['wifi'] as Map<String, dynamic>?;
    return SessionInfo(
      name: j['name']?.toString() ?? 'bettercap-wifi',
      version: j['version']?.toString() ?? '',
      os: j['os']?.toString() ?? '',
      // absent (older backend) → assume supported, don't nag
      injectionSupported: j['injection_supported'] != false,
      active: j['active'] == true,
      modules: mods,
      accessPoints: wifi == null ? const [] : _apsFrom(wifi),
    );
  }
}

class ModuleInfo {
  final String name;
  final bool running;
  final List<int> channels;
  ModuleInfo({required this.name, required this.running, this.channels = const []});

  factory ModuleInfo.fromJson(Map<String, dynamic> j) {
    final state = j['state'] as Map<String, dynamic>?;
    final chans = (state?['channels'] as List<dynamic>?)
            ?.map((e) => (e as num).toInt())
            .toList() ??
        const <int>[];
    return ModuleInfo(
      name: j['name']?.toString() ?? '',
      running: j['running'] == true,
      channels: chans,
    );
  }
}

class AccessPoint {
  final String mac;
  final String essid;
  final String vendor;
  final int channel;
  final int rssi;
  final int sent;
  final int received;
  final String encryption;
  final String cipher;
  final String authentication;
  final bool handshake;
  final Map<String, String> wps;
  final List<WifiClient> clients;

  AccessPoint({
    required this.mac,
    required this.essid,
    required this.vendor,
    required this.channel,
    required this.rssi,
    required this.sent,
    required this.received,
    required this.encryption,
    required this.cipher,
    required this.authentication,
    required this.handshake,
    required this.wps,
    required this.clients,
  });

  bool get hidden => essid.isEmpty || essid == '<hidden>';
  String get displayName => hidden ? '<hidden>' : essid;
  bool get open => encryption.isEmpty || encryption.toUpperCase() == 'OPEN';

  factory AccessPoint.fromJson(Map<String, dynamic> j) {
    return AccessPoint(
      mac: j['mac']?.toString() ?? '',
      essid: j['hostname']?.toString() ?? '',
      vendor: j['vendor']?.toString() ?? '',
      channel: (j['channel'] as num?)?.toInt() ?? 0,
      rssi: (j['rssi'] as num?)?.toInt() ?? 0,
      sent: (j['sent'] as num?)?.toInt() ?? 0,
      received: (j['received'] as num?)?.toInt() ?? 0,
      encryption: j['encryption']?.toString() ?? '',
      cipher: j['cipher']?.toString() ?? '',
      authentication: j['authentication']?.toString() ?? '',
      handshake: j['handshake'] == true,
      wps: (j['wps'] as Map<String, dynamic>?)
              ?.map((k, v) => MapEntry(k, v.toString())) ??
          const {},
      clients: (j['clients'] as List<dynamic>?)
              ?.whereType<Map<String, dynamic>>()
              .map(WifiClient.fromJson)
              .toList() ??
          const [],
    );
  }
}

class WifiClient {
  final String mac;
  final String vendor;
  final int rssi;
  final int sent;
  final int received;

  WifiClient({
    required this.mac,
    required this.vendor,
    required this.rssi,
    required this.sent,
    required this.received,
  });

  factory WifiClient.fromJson(Map<String, dynamic> j) {
    return WifiClient(
      mac: j['mac']?.toString() ?? '',
      vendor: j['vendor']?.toString() ?? '',
      rssi: (j['rssi'] as num?)?.toInt() ?? 0,
      sent: (j['sent'] as num?)?.toInt() ?? 0,
      received: (j['received'] as num?)?.toInt() ?? 0,
    );
  }
}

class ApEvent {
  final String tag;
  final DateTime time;
  final dynamic data;

  ApEvent({required this.tag, required this.time, this.data});

  factory ApEvent.fromJson(Map<String, dynamic> j) {
    return ApEvent(
      tag: j['tag']?.toString() ?? '',
      time: DateTime.tryParse(j['time']?.toString() ?? '')?.toLocal() ??
          DateTime.now(),
      data: j['data'],
    );
  }

  String get summary {
    final d = data;
    if (d is Map && d['Message'] != null) return d['Message'].toString();
    if (d is Map && d['message'] != null) return d['message'].toString();
    if (d == null) return '';
    return d.toString();
  }
}

/// Result of GET /api/handshakes: the captures plus the pcap file they go to.
class HandshakesResult {
  final String file;
  final List<HandshakeInfo> items;
  HandshakesResult({required this.file, required this.items});
}

/// A captured 802.11 key exchange, from GET /api/handshakes — tied to an AP and
/// (when known) a client station.
class HandshakeInfo {
  final String apBssid;
  final String apEssid;
  final int channel;
  final String encryption;
  final bool apKeyMaterial;
  final String station; // client MAC, "" for an AP-level capture
  final String stationVendor;
  final bool pmkid;
  final bool half;
  final bool complete;
  final int unsaved;

  HandshakeInfo({
    required this.apBssid,
    required this.apEssid,
    required this.channel,
    required this.encryption,
    required this.apKeyMaterial,
    required this.station,
    required this.stationVendor,
    required this.pmkid,
    required this.half,
    required this.complete,
    required this.unsaved,
  });

  bool get apHidden => apEssid.isEmpty || apEssid == '<hidden>';
  String get apName => apHidden ? '<hidden>' : apEssid;

  /// Best-to-weakest label describing what was captured.
  String get kind {
    if (pmkid) return 'PMKID';
    if (complete) return 'FULL';
    if (half) return 'HALF';
    return 'KEY';
  }

  /// Stable identity of a capture target (one AP/client pair).
  String get key => '${apBssid.toLowerCase()}|${station.toLowerCase()}';

  /// Higher = more useful capture (PMKID > full > half > flag only).
  int get strength {
    if (pmkid) return 3;
    if (complete) return 2;
    if (half) return 1;
    return 0;
  }

  factory HandshakeInfo.fromJson(Map<String, dynamic> j) {
    return HandshakeInfo(
      apBssid: j['ap_bssid']?.toString() ?? '',
      apEssid: j['ap_essid']?.toString() ?? '',
      channel: (j['channel'] as num?)?.toInt() ?? 0,
      encryption: j['encryption']?.toString() ?? '',
      apKeyMaterial: j['ap_key_material'] == true,
      station: j['station']?.toString() ?? '',
      stationVendor: j['station_vendor']?.toString() ?? '',
      pmkid: j['pmkid'] == true,
      half: j['half'] == true,
      complete: j['complete'] == true,
      unsaved: (j['unsaved'] as num?)?.toInt() ?? 0,
    );
  }
}

extension _FirstOrNull<E> on Iterable<E> {
  E? get firstOrNull => isEmpty ? null : first;
}
