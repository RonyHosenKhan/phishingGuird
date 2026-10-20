import 'package:flutter/material.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  int _selectedIndex = 0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF0F172A),
        elevation: 0,
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFF06B6D4), Color(0xFF6366F1)],
                ),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.shield_outlined, color: Colors.white, size: 20),
            ),
            const SizedBox(width: 10),
            const Text(
              "PhishGuard AI",
              style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
            ),
          ],
        ),
        actions: [
          Container(
            margin: const EdgeInsets.only(right: 14),
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: Colors.emerald.withOpacity(0.15),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: Colors.emerald.withOpacity(0.3)),
            ),
            child: const Row(
              children: [
                Icon(Icons.circle, color: Colors.greenAccent, size: 8),
                SizedBox(width: 6),
                Text(
                  "ACTIVE",
                  style: TextStyle(color: Colors.greenAccent, fontSize: 11, fontWeight: FontWeight.bold),
                ),
              ],
            ),
          )
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Student & Course Info Card
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: const Color(0xFF1E293B).withOpacity(0.6),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: Colors.white10),
              ),
              child: const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text("Student: Tamanna Akter (21CSE012)", style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13, color: Colors.white)),
                  SizedBox(height: 2),
                  Text("Mobile Computing Lab (8th Sem) - On-Device AI Threat Detection", style: TextStyle(fontSize: 11, color: Colors.white60)),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Live Risk Gauge Card
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFF0F172A), Color(0xFF1E293B)],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: Colors.white12),
              ),
              child: Column(
                children: [
                  const Text("Device Security Risk Level", style: TextStyle(fontSize: 13, color: Colors.white70)),
                  const SizedBox(height: 12),
                  Stack(
                    alignment: Alignment.center,
                    children: [
                      SizedBox(
                        width: 130,
                        height: 130,
                        child: CircularProgressIndicator(
                          value: 0.04,
                          strokeWidth: 12,
                          backgroundColor: Colors.white10,
                          valueColor: const AlwaysStoppedAnimation<Color>(Colors.greenAccent),
                        ),
                      ),
                      const Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text("4.0%", style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: Colors.white)),
                          Text("SAFE", style: TextStyle(fontSize: 10, color: Colors.greenAccent, fontWeight: FontWeight.bold)),
                        ],
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  const Row(
                    mainAxisAlignment: MainAxisAlignment.spaceAround,
                    children: [
                      Text("Latency: 12.4 ms", style: TextStyle(fontSize: 11, color: Colors.white60)),
                      Text("Privacy: 100% On-Device", style: TextStyle(fontSize: 11, color: Color(0xFF38BDF8))),
                    ],
                  )
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Listener Services Status
            const Text("Active Background Listeners", style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold, color: Colors.white)),
            const SizedBox(height: 8),
            _buildServiceItem(
              icon: Icons.notifications_active_outlined,
              title: "NotificationListenerService",
              subtitle: "Intercepts SMS, WhatsApp, Messenger, Gmail",
              status: "HOOKED",
            ),
            const SizedBox(height: 8),
            _buildServiceItem(
              icon: Icons.visibility_outlined,
              title: "AccessibilityService",
              subtitle: "Inspects on-screen URLs and deep-links",
              status: "ACTIVE",
            ),
          ],
        ),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (idx) => setState(() => _selectedIndex = idx),
        backgroundColor: const Color(0xFF0F172A),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.shield_outlined), label: "Shield"),
          NavigationDestination(icon: Icon(Icons.search), label: "Scanner"),
          NavigationDestination(icon: Icon(Icons.history), label: "Audit DB"),
          NavigationDestination(icon: Icon(Icons.description_outlined), label: "Lab Docs"),
        ],
      ),
    );
  }

  Widget _buildServiceItem({
    required IconData icon,
    required String title,
    required String subtitle,
    required String status,
  }) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF0F172A),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: const Color(0xFF38BDF8).withOpacity(0.12),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, color: const Color(0xFF38BDF8), size: 18),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13, color: Colors.white)),
                Text(subtitle, style: const TextStyle(fontSize: 10, color: Colors.white54)),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
            decoration: BoxDecoration(
              color: Colors.greenAccent.withOpacity(0.12),
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: Colors.greenAccent.withOpacity(0.3)),
            ),
            child: Text(status, style: const TextStyle(color: Colors.greenAccent, fontSize: 9, fontWeight: FontWeight.bold)),
          )
        ],
      ),
    );
  }
}
