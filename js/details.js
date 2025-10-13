// details.js: Populate detailed scan view

(function() {
  const menuToggle = document.getElementById('menuToggle');
  const sidebar = document.getElementById('sidebar');
  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
  }

  // Read scan_id from URL ?scan_id=YYYYMMDDTHHMMSSZ
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get('scan_id');

  async function loadDetails() {
    if (!scanId) {
      document.getElementById('detailsTarget').textContent = 'Unknown';
      return;
    }
    try {
      const data = await Auth.authenticatedFetch(`/api/scans/${scanId}`, { method: 'GET' });
      renderDetails(data);
    } catch (err) {
      console.error('Failed to load scan details:', err);
      alert('Failed to load details.');
    }
  }

  function renderDetails(data) {
    document.getElementById('detailsTarget').textContent = data.target || 'unknown';
    document.getElementById('detailsTimestamp').textContent = data.timestamp || scanId;
    document.getElementById('detailsTotal').textContent = data.total_cves || 0;

    document.getElementById('detailsCritical').textContent = data.critical_count || 0;
    document.getElementById('detailsHigh').textContent = data.high_count || 0;
    document.getElementById('detailsMedium').textContent = data.medium_count || 0;
    document.getElementById('detailsLow').textContent = data.low_count || 0;
    document.getElementById('detailsUnknown').textContent = data.unknown_count || 0;

    const container = document.getElementById('detailsVulns');
    const findings = data.findings || [];
    if (!findings.length) {
      container.innerHTML = '<div class="no-vulnerabilities">No vulnerabilities found.</div>';
      return;
    }
    container.innerHTML = findings.map(f => {
      const sevClass = (f.severity || 'Unknown').toLowerCase();
      const title = f.title || f.description || 'N/A';
      const cve = f.cve || 'N/A';
      const cvss = (f.cvss_v3 && f.cvss_v3 !== 'N/A') ? `CVSS v3: ${f.cvss_v3}` : '';
      const source = f.source_tool || 'Unknown';
      return `
        <div class="vulnerability-item ${sevClass}-item">
          <div class="vuln-header">
            <div>
              <strong>${cve}</strong>
              <span class="severity-badge ${sevClass}">${(f.severity || 'Unknown').toUpperCase()}</span>
            </div>
            <div class="cvss-scores">${cvss}</div>
          </div>
          <p><strong>Source:</strong> ${source}</p>
          <p class="vuln-description"><strong>Description:</strong> ${title}</p>
        </div>
      `;
    }).join('');

    // CSV download
    const btn = document.getElementById('downloadCsvDetails');
    if (btn) {
      btn.addEventListener('click', async () => {
        try {
          const response = await Auth.authenticatedFetch(`/api/scans/${scanId}/download-csv`, { method: 'GET' });
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `scan_results_${scanId}.csv`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
        } catch (e) {
          console.error('CSV download failed', e);
          alert('CSV download failed');
        }
      });
    }
  }

  window.addEventListener('DOMContentLoaded', () => {
    // Require auth
    Auth.requireAuth();
    Auth.updateNavbarProfile();
    loadDetails();
  });
})();
