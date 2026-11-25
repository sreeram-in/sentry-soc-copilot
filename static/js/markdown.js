// Minimal markdown-ish renderer for AI replies: headers, **bold**, "- " bullet
// lists, and paragraphs. Escapes HTML first, so it's safe against any text the
// model returns.
window.sentryFormat = function (raw) {
  if (!raw) return '';

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function inline(s) {
    s = escapeHtml(s);
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/^#{1,6}\s*/, '');
    return s;
  }

  var blocks = raw.trim().split(/\n\s*\n/);
  return blocks.map(function (block) {
    var lines = block.split('\n').filter(Boolean);
    var isHeading = lines.length === 1 && /^#{1,6}\s+/.test(lines[0]);
    var isList = lines.length > 0 && lines.every(function (l) { return /^\s*[-*]\s+/.test(l); });

    if (isHeading) return '<strong>' + inline(lines[0]) + '</strong>';
    if (isList) {
      return '<ul>' + lines.map(function (l) {
        return '<li>' + inline(l.replace(/^\s*[-*]\s+/, '')) + '</li>';
      }).join('') + '</ul>';
    }
    return '<p>' + lines.map(inline).join('<br>') + '</p>';
  }).join('');
};