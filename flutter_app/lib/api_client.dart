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
  final bool active;
  final List<ModuleInfo> modules;
  final List<AccessPoint> accessPoints;

  SessionInfo({
    required this.name,
    required this.version,
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

extension _FirstOrNull<E> on Iterable<E> {
  E? get firstOrNull => isEmpty ? null : first;
}
