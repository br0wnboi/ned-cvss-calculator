// CVSS Translation Logic
window.CVSS_Translation = {
    translate3to4: function(m3) {
        const m4 = {};
        m4.AV = m3.AV;
        m4.AC = m3.AC;
        m4.PR = m3.PR;
        m4.AT = 'N'; // New metric in 4.0, default to None
        m4.UI = m3.UI === 'R' ? 'P' : 'N'; // R -> P (Passive is safe approximation)
        
        // Map Vulnerable System Impacts directly
        m4.VC = m3.C;
        m4.VI = m3.I;
        m4.VA = m3.A;

        // Map Subsequent System Impacts if Scope was Changed
        if (m3.S === 'C') {
            m4.SC = m3.C;
            m4.SI = m3.I;
            m4.SA = m3.A;
        } else {
            m4.SC = 'N';
            m4.SI = 'N';
            m4.SA = 'N';
        }
        return m4;
    },

    translate4to3: function(m4) {
        const m3 = {};
        m3.AV = m4.AV;
        m3.AC = m4.AC;
        m3.PR = m4.PR;
        
        // UI mapping
        m3.UI = (m4.UI === 'P' || m4.UI === 'A') ? 'R' : 'N';

        // Scope mapping based on any subsequent impacts (or safety)
        const subsequentImpact = (m4.SC !== 'N' || m4.SI !== 'N' || m4.SA !== 'N' || m4.SI === 'S' || m4.SA === 'S');
        m3.S = subsequentImpact ? 'C' : 'U';

        // Impact mapping (max of Vulnerable vs Subsequent)
        const severityOrder = { 'N': 0, 'L': 1, 'H': 2 };
        const maxSev = (v1, v2) => {
            // Safety 'S' maps to High for approximation
            const val1 = v1 === 'S' ? 'H' : v1;
            const val2 = v2 === 'S' ? 'H' : v2;
            return severityOrder[val1] >= severityOrder[val2] ? val1 : val2;
        };

        m3.C = maxSev(m4.VC, m4.SC);
        m3.I = maxSev(m4.VI, m4.SI);
        m3.A = maxSev(m4.VA, m4.SA);
        return m3;
    }
};
