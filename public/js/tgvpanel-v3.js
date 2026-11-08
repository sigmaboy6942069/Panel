(function () {
  window.hkvmToast = function (message, type) {
    var existing = document.getElementById('hkvmToastContainer');
    if (!existing) {
      existing = document.createElement('div');
      existing.id = 'hkvmToastContainer';
      existing.style.cssText =
        'position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:8px;max-width:380px;';
      document.body.appendChild(existing);
    }
    var el = document.createElement('div');
    var bg =
      type === 'error'
        ? 'rgba(239,68,68,0.95)'
        : type === 'warning'
        ? 'rgba(245,158,11,0.95)'
        : 'rgba(16,185,129,0.95)';
    el.style.cssText =
      'padding:11px 16px;border-radius:10px;color:#fff;font-size:13px;font-weight:500;box-shadow:0 10px 25px rgba(0,0,0,0.35);background:' +
      bg +
      ';';
    el.textContent = message;
    existing.appendChild(el);
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 4000);
  };

  window.hkvmApi = async function (url, options) {
    var opts = Object.assign({ method: 'GET', cache: 'no-store', headers: {} }, options || {});
    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta && csrfMeta.content) {
      opts.headers['X-CSRF-Token'] = csrfMeta.content;
    }
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    var res = await fetch(url, opts);
    var data = {};
    try {
      data = await res.json();
    } catch (_e) {
      data = {};
    }
    if (!res.ok) {
      throw new Error(data.error || 'Request failed with HTTP ' + res.status);
    }
    return data;
  };

  window.hkvmEsc = function (val) {
    return String(val == null ? '' : val)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  };

  async function refreshHeaderNotifications() {
    var dot = document.getElementById('notifDot');
    var list = document.getElementById('notifList');
    if (!dot || !list) return;
    try {
      var data = await window.hkvmApi('/api/v1/notifications');
      var items = data.notifications || [];
      var unread = items.filter(function (n) {
        return !n.is_read;
      });
      dot.style.display = unread.length > 0 ? 'block' : 'none';
      if (items.length === 0) {
        list.innerHTML =
          '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:12px;">No notifications</div>';
        return;
      }
      list.innerHTML = items
        .slice(0, 10)
        .map(function (n) {
          return (
            '<div style="padding:10px 14px;border-bottom:1px solid var(--border-subtle);opacity:' +
            (n.is_read ? '0.65' : '1') +
            ';">' +
            '<div style="font-size:12px;font-weight:600;color:var(--text-primary);">' +
            window.hkvmEsc(n.title) +
            '</div>' +
            '<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">' +
            window.hkvmEsc(n.message) +
            '</div>' +
            '</div>'
          );
        })
        .join('');
    } catch (_e) {
      // Ignore unauthenticated pages
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    refreshHeaderNotifications();
  });
})();
