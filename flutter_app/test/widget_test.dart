import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/widgets.dart';

import 'package:bettercap_wifi/main.dart';

void main() {
  testWidgets('app renders its title', (tester) async {
    await tester.pumpWidget(const BettercapWifiApp());
    expect(find.text('bettercap-wifi'), findsWidgets);
    // dispose the tree so the periodic refresh timer is cancelled
    await tester.pumpWidget(const SizedBox());
  });
}
