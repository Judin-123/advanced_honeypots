"""
Integrated Adaptive Dashboard - Combines real data dashboard with adaptive honeypot
"""
import threading
from flask import jsonify
from real_dashboard import RealDataDashboard
from adaptive_honeypot_system import AdaptiveHoneypotSystem

class IntegratedAdaptiveDashboard(RealDataDashboard):
    """Dashboard that includes adaptive honeypot capabilities"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize adaptive system
        self.adaptive_system = AdaptiveHoneypotSystem()
        
        # Override routes to include adaptive data
        self.setup_adaptive_routes()
    
    def setup_adaptive_routes(self):
        """Add adaptive system routes"""
        
        @self.app.route('/api/adaptive-status')
        def api_adaptive_status():
            return jsonify(self.adaptive_system.get_status())
        
        @self.app.route('/api/switch-profile/<profile>')
        def api_switch_profile(profile):
            if profile in self.adaptive_system.profiles:
                self.adaptive_system.switch_profile(profile)
                return jsonify({'success': True, 'new_profile': profile})
            return jsonify({'success': False, 'error': 'Invalid profile'})
    
    def process_log_line(self, line, source_file):
        """Override to include adaptive processing"""
        # Call parent method
        super().process_log_line(line, source_file)
        
        # Process with adaptive system
        if self.real_sessions:
            latest_session = list(self.real_sessions)[-1]
            self.adaptive_system.process_new_session(latest_session)
    
    def get_html(self):
        """Enhanced HTML with adaptive controls"""
        return super().get_html().replace(
            '<div class="controls">',
            '''
            <div class="section">
                <div class="section-title">
                    <i class="fas fa-brain"></i>
                    Adaptive System Status
                </div>
                <div id="adaptive-status">Loading adaptive status...</div>
                <div style="margin-top: 16px;">
                    <button class="refresh-btn" onclick="switchProfile('minimal')">Minimal</button>
                    <button class="refresh-btn" onclick="switchProfile('standard')">Standard</button>
                    <button class="refresh-btn" onclick="switchProfile('aggressive')">Aggressive</button>
                    <button class="refresh-btn" onclick="switchProfile('deceptive')">Deceptive</button>
                </div>
            </div>
            
            <div class="controls">
            '''
        ).replace(
            'setInterval(refreshRealData, 5000);',
            '''
            setInterval(refreshRealData, 5000);
            setInterval(updateAdaptiveStatus, 10000);
            
            async function updateAdaptiveStatus() {
                const data = await fetchRealData('/api/adaptive-status');
                if (data) {
                    document.getElementById('adaptive-status').innerHTML = `
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                            <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                                <div style="color: #999; font-size: 0.8rem;">Current Profile</div>
                                <div style="color: #00FF88; font-size: 1.2rem; font-weight: 700;">${data.current_profile.toUpperCase()}</div>
                            </div>
                            <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                                <div style="color: #999; font-size: 0.8rem;">Services Active</div>
                                <div style="color: #FFF; font-size: 1.2rem; font-weight: 700;">${data.profile_config.services.length}</div>
                            </div>
                            <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                                <div style="color: #999; font-size: 0.8rem;">Deception Level</div>
                                <div style="color: #FFAA00; font-size: 1.2rem; font-weight: 700;">${data.profile_config.deception_level}/10</div>
                            </div>
                            <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                                <div style="color: #999; font-size: 0.8rem;">Unique Attackers</div>
                                <div style="color: #FF4444; font-size: 1.2rem; font-weight: 700;">${data.unique_attackers}</div>
                            </div>
                        </div>
                    `;
                }
            }
            
            async function switchProfile(profile) {
                const response = await fetch(`/api/switch-profile/${profile}`);
                const data = await response.json();
                if (data.success) {
                    alert(`✅ Switched to ${profile.toUpperCase()} profile`);
                    updateAdaptiveStatus();
                } else {
                    alert(`❌ Failed to switch profile: ${data.error}`);
                }
            }
            '''
        )

def main():
    """Run integrated adaptive dashboard"""
    print("=" * 80)
    print("🧠 INTEGRATED ADAPTIVE HONEYPOT DASHBOARD")
    print("=" * 80)
    print()
    print("🎯 Features:")
    print("   • Real-time data monitoring")
    print("   • ML-powered threat analysis")
    print("   • Adaptive behavior profiles")
    print("   • Intelligent deception tactics")
    print("   • Manual profile switching")
    print("   • Automatic IP blocking")
    print()
    
    dashboard = IntegratedAdaptiveDashboard()
    dashboard.run(port=5003)

if __name__ == '__main__':
    main()