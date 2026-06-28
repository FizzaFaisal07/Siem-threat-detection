"""
Additional API Routes for SIEM Enterprise
"""

from flask import request, jsonify
from datetime import datetime, timedelta

def register_api_routes(app, db, detector, packet_capture, nmap_scanner, auth):
    
    @app.route('/api/alerts/resolve/<int:alert_id>', methods=['POST'])
    def resolve_alert(alert_id):
        """Mark an alert as resolved"""
        db.resolve_alert(alert_id)
        return jsonify({'status': 'resolved'})
    
    @app.route('/api/alerts/stats/weekly')
    def weekly_stats():
        """Get weekly alert statistics"""
        stats = db.get_weekly_stats()
        return jsonify(stats)
    
    @app.route('/api/threats/top-sources')
    def top_threat_sources():
        """Get top threat sources"""
        sources = db.get_top_threat_sources(limit=10)
        return jsonify(sources)
    
    @app.route('/api/alerts/by-type')
    def alerts_by_type():
        """Get alerts grouped by type"""
        data = db.get_alerts_by_type_grouped()
        return jsonify(data)
    
    @app.route('/api/system/health')
    def system_health():
        """Get system health status"""
        health = {
            'status': 'healthy',
            'database': db.check_connection(),
            'packet_capture': packet_capture.is_active(),
            'nmap': nmap_scanner.is_available(),
            'auth': auth.is_active(),
            'timestamp': datetime.now().isoformat()
        }
        return jsonify(health)