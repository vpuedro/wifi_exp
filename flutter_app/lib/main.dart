import 'dart:async';
import 'package:flutter/material.dart';

import 'api_client.dart';

void main() => runApp(const BettercapWifiApp());

class BettercapWifiApp extends StatelessWidget {
  const BettercapWifiApp({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF00E5A0),
      brightness: Brightness.dark,
    );
    return MaterialApp(
      title: 'bettercap-wifi',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: scheme,
        useMaterial3: true,
        fontFamily: 'monospace',
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final ApiClient _api = ApiClient();
  Timer? _timer;
  bool _busy = false;

  SessionInfo? _session;
  List<ApEvent> _events = const [];
  String? _error;
  int _tab = 0;

  @override
  void initState() {
    super.initState();
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 3), (_) => _refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    _api.close();
    super.dispose();
  }

  Future<void> _refresh() async {
    if (_busy) return;
    _busy = true;
    try {
      final session = await _api.getSession();
      final events = await _api.getEvents(n: 100);
      if (!mounted) return;
      setState(() {
        _session = session;
        _events = events.reversed.toList();
        _error = null;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = e.toString());
    } finally {
      _busy = false;
    }
  }

  Future<void> _run(String cmd, {String? ok}) async {
    try {
      await _api.run(cmd);
      _snack(ok ?? '✓ $cmd');
      await _refresh();
    } catch (e) {
      _snack('✗ $cmd — $e', error: true);
    }
  }

  void _snack(String msg, {bool error = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(
        content: Text(msg),
        behavior: SnackBarBehavior.floating,
        backgroundColor: error ? Colors.red.shade900 : null,
      ));
  }

  @override
  Widget build(BuildContext context) {
    final connected = _error == null && _session != null;
    final aps = List<AccessPoint>.of(_session?.accessPoints ?? const []);
    aps.sort((a, b) => b.rssi.compareTo(a.rssi));

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 12,
        title: Row(children: [
          Icon(Icons.circle, size: 12, color: connected ? Colors.greenAccent : Colors.redAccent),
          const SizedBox(width: 8),
          const Text('bettercap-wifi'),
          if (_session != null) ...[
            const SizedBox(width: 8),
            Text('v${_session!.version}',
                style: const TextStyle(fontSize: 12, color: Colors.white54)),
          ],
        ]),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _refresh),
          IconButton(icon: const Icon(Icons.settings), onPressed: _openSettings),
        ],
      ),
      body: Column(children: [
        if (_error != null)
          Material(
            color: Colors.red.shade900,
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Row(children: [
                const Icon(Icons.warning_amber, size: 18),
                const SizedBox(width: 8),
                Expanded(child: Text('Backend injoignable — $_error')),
              ]),
            ),
          ),
        _controlBar(connected),
        const Divider(height: 1),
        Expanded(child: _body(aps)),
      ]),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: [
          NavigationDestination(
            icon: Badge(
              label: Text('${aps.length}'),
              isLabelVisible: aps.isNotEmpty,
              child: const Icon(Icons.wifi),
            ),
            label: 'Points d\'accès',
          ),
          const NavigationDestination(icon: Icon(Icons.list_alt), label: 'Événements'),
          const NavigationDestination(icon: Icon(Icons.terminal), label: 'Console'),
        ],
      ),
    );
  }

  Widget _controlBar(bool connected) {
    final running = _session?.reconRunning ?? false;
    final channels = _session?.wifiModule?.channels ?? const [];
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Row(children: [
        FilledButton.icon(
          onPressed: connected
              ? () => _run(running ? 'wifi.recon off' : 'wifi.recon on')
              : null,
          icon: Icon(running ? Icons.stop : Icons.play_arrow),
          label: Text(running ? 'Recon ON' : 'Recon OFF'),
          style: FilledButton.styleFrom(
            backgroundColor: running ? Colors.greenAccent.shade700 : null,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            channels.isEmpty ? 'hopping: —' : 'canaux: ${channels.join(",")}',
            style: const TextStyle(fontSize: 12, color: Colors.white54),
            overflow: TextOverflow.ellipsis,
          ),
        ),
        IconButton(
          tooltip: 'Régler le(s) canal(aux)',
          icon: const Icon(Icons.tune),
          onPressed: connected ? _promptChannel : null,
        ),
      ]),
    );
  }

  Widget _body(List<AccessPoint> aps) {
    switch (_tab) {
      case 1:
        return _eventsView();
      case 2:
        return ConsolePage(onRun: (c) => _run(c));
      default:
        return _apsView(aps);
    }
  }

  Widget _apsView(List<AccessPoint> aps) {
    if (aps.isEmpty) {
      return const _Empty(
        icon: Icons.wifi_find,
        text: 'Aucun point d\'accès.\nLance "Recon ON" pour scanner.',
      );
    }
    return RefreshIndicator(
      onRefresh: _refresh,
      child: ListView.builder(
        padding: const EdgeInsets.only(bottom: 24),
        itemCount: aps.length,
        itemBuilder: (_, i) => _ApCard(ap: aps[i], onRun: _run),
      ),
    );
  }

  Widget _eventsView() {
    return Column(children: [
      Align(
        alignment: Alignment.centerRight,
        child: TextButton.icon(
          onPressed: () async {
            await _api.clearEvents();
            _refresh();
          },
          icon: const Icon(Icons.clear_all, size: 18),
          label: const Text('Vider'),
        ),
      ),
      Expanded(
        child: _events.isEmpty
            ? const _Empty(icon: Icons.list_alt, text: 'Aucun événement.')
            : ListView.separated(
                itemCount: _events.length,
                separatorBuilder: (_, _) => const Divider(height: 1),
                itemBuilder: (_, i) {
                  final e = _events[i];
                  return ListTile(
                    dense: true,
                    leading: Text(_hhmmss(e.time),
                        style: const TextStyle(fontSize: 11, color: Colors.white38)),
                    title: Text(e.tag,
                        style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                    subtitle: e.summary.isEmpty ? null : Text(e.summary),
                  );
                },
              ),
      ),
    ]);
  }

  Future<void> _promptChannel() async {
    final ctrl = TextEditingController();
    final v = await showDialog<String>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Canaux'),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          decoration: const InputDecoration(
            hintText: 'ex: 1,6,11  —  vide = hopping',
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, 'clear'),
              child: const Text('Hopping (clear)')),
          FilledButton(
              onPressed: () => Navigator.pop(context, ctrl.text.trim()),
              child: const Text('Appliquer')),
        ],
      ),
    );
    if (v == null) return;
    _run(v.isEmpty || v == 'clear'
        ? 'wifi.recon.channel clear'
        : 'wifi.recon.channel $v');
  }

  Future<void> _openSettings() async {
    final url = TextEditingController(text: _api.baseUrl);
    final tok = TextEditingController(text: _api.token);
    final saved = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Connexion au backend'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(
            controller: url,
            decoration: const InputDecoration(labelText: 'URL', hintText: 'http://127.0.0.1:8081'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: tok,
            decoration: const InputDecoration(labelText: 'Jeton API (optionnel)'),
          ),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Annuler')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('OK')),
        ],
      ),
    );
    if (saved == true) {
      setState(() {
        _api.baseUrl = url.text.trim();
        _api.token = tok.text.trim();
      });
      _refresh();
    }
  }
}

class _ApCard extends StatelessWidget {
  final AccessPoint ap;
  final Future<void> Function(String, {String? ok}) onRun;
  const _ApCard({required this.ap, required this.onRun});

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      child: ExpansionTile(
        tilePadding: const EdgeInsets.symmetric(horizontal: 14),
        title: Row(children: [
          Expanded(
            child: Text(
              ap.displayName,
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontStyle: ap.hidden ? FontStyle.italic : FontStyle.normal,
                color: ap.hidden ? Colors.white38 : null,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (ap.handshake)
            const Padding(
              padding: EdgeInsets.only(left: 6),
              child: Icon(Icons.vpn_key, size: 16, color: Colors.amberAccent),
            ),
          _rssiBadge(ap.rssi),
        ]),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 4),
          child: Wrap(spacing: 6, runSpacing: 4, children: [
            Text(ap.mac, style: const TextStyle(fontSize: 11, color: Colors.white54)),
            _chip('CH ${ap.channel}'),
            _chip(ap.open ? 'OPEN' : ap.encryption,
                color: ap.open ? Colors.orange : Colors.blueGrey),
            if (ap.clients.isNotEmpty) _chip('${ap.clients.length} clients'),
            if (ap.wps.isNotEmpty) _chip('WPS', color: Colors.purple),
          ]),
        ),
        childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 12),
        children: [
          if (ap.vendor.isNotEmpty)
            Align(
              alignment: Alignment.centerLeft,
              child: Text(ap.vendor,
                  style: const TextStyle(fontSize: 12, color: Colors.white54)),
            ),
          const SizedBox(height: 8),
          Wrap(spacing: 8, children: [
            OutlinedButton.icon(
              onPressed: () => onRun('wifi.deauth ${ap.mac}', ok: 'deauth → ${ap.displayName}'),
              icon: const Icon(Icons.flash_on, size: 16),
              label: const Text('Deauth'),
            ),
            OutlinedButton.icon(
              onPressed: () => onRun('wifi.assoc ${ap.mac}', ok: 'assoc → ${ap.displayName}'),
              icon: const Icon(Icons.key, size: 16),
              label: const Text('Assoc (PMKID)'),
            ),
            OutlinedButton.icon(
              onPressed: () => onRun('wifi.show.wps ${ap.mac}'),
              icon: const Icon(Icons.info_outline, size: 16),
              label: const Text('WPS'),
            ),
          ]),
          if (ap.clients.isNotEmpty) ...[
            const Divider(),
            ...ap.clients.map((c) => ListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.smartphone, size: 18),
                  title: Text(c.mac, style: const TextStyle(fontSize: 12)),
                  subtitle: c.vendor.isEmpty ? null : Text(c.vendor, style: const TextStyle(fontSize: 11)),
                  trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                    _rssiBadge(c.rssi),
                    IconButton(
                      tooltip: 'Deauth ce client',
                      icon: const Icon(Icons.flash_on, size: 16),
                      onPressed: () => onRun('wifi.deauth ${c.mac}', ok: 'deauth client ${c.mac}'),
                    ),
                  ]),
                )),
          ],
        ],
      ),
    );
  }
}

Widget _chip(String text, {Color? color}) => Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: (color ?? Colors.blueGrey).withValues(alpha: 0.25),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(text, style: const TextStyle(fontSize: 11)),
    );

Widget _rssiBadge(int rssi) {
  Color c;
  if (rssi >= -60) {
    c = Colors.greenAccent;
  } else if (rssi >= -75) {
    c = Colors.amberAccent;
  } else {
    c = Colors.redAccent;
  }
  return Text('$rssi dBm',
      style: TextStyle(fontSize: 12, color: c, fontWeight: FontWeight.bold));
}

class ConsolePage extends StatefulWidget {
  final Future<void> Function(String) onRun;
  const ConsolePage({super.key, required this.onRun});
  @override
  State<ConsolePage> createState() => _ConsolePageState();
}

class _ConsolePageState extends State<ConsolePage> {
  final TextEditingController _ctrl = TextEditingController();
  final List<String> _history = [];

  static const _quick = [
    'wifi.recon on',
    'wifi.recon off',
    'wifi.clear',
    'wifi.show',
    'set wifi.rssi.min -70',
    'wifi.recon.channel clear',
  ];

  void _send([String? c]) {
    final cmd = (c ?? _ctrl.text).trim();
    if (cmd.isEmpty) return;
    setState(() => _history.insert(0, cmd));
    widget.onRun(cmd);
    _ctrl.clear();
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.all(12),
        child: Row(children: [
          Expanded(
            child: TextField(
              controller: _ctrl,
              onSubmitted: _send,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                isDense: true,
                hintText: 'wifi.deauth aa:bb:cc:dd:ee:ff',
                prefixText: '» ',
              ),
            ),
          ),
          const SizedBox(width: 8),
          FilledButton(onPressed: _send, child: const Text('Envoyer')),
        ]),
      ),
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Wrap(
          spacing: 8,
          children: _quick
              .map((c) => ActionChip(label: Text(c), onPressed: () => _send(c)))
              .toList(),
        ),
      ),
      const Divider(),
      Expanded(
        child: _history.isEmpty
            ? const _Empty(icon: Icons.terminal, text: 'Les commandes envoyées apparaîtront ici.')
            : ListView.builder(
                itemCount: _history.length,
                itemBuilder: (_, i) => ListTile(
                  dense: true,
                  leading: const Icon(Icons.chevron_right, size: 18),
                  title: Text(_history[i], style: const TextStyle(fontSize: 13)),
                ),
              ),
      ),
    ]);
  }
}

class _Empty extends StatelessWidget {
  final IconData icon;
  final String text;
  const _Empty({required this.icon, required this.text});
  @override
  Widget build(BuildContext context) => Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, size: 48, color: Colors.white24),
          const SizedBox(height: 12),
          Text(text, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white38)),
        ]),
      );
}

String _hhmmss(DateTime t) =>
    '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';
