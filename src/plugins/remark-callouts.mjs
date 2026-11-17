// Turns GitHub-style alerts (> [!NOTE], > [!WARNING] ...) into styled callouts,
// so reports copied from GitHub render the same way here without editing them.
const KINDS = ['NOTE', 'TIP', 'IMPORTANT', 'WARNING', 'CAUTION'];

function walk(node, fn) {
  fn(node);
  if (node.children) node.children.forEach((c) => walk(c, fn));
}

export default function remarkCallouts() {
  return (tree) => {
    walk(tree, (node) => {
      if (node.type !== 'blockquote') return;
      const first = node.children?.[0];
      const text = first?.type === 'paragraph' ? first.children?.[0] : null;
      if (!text || text.type !== 'text') return;
      const m = text.value.match(/^\[!(\w+)\]\s*/);
      if (!m || !KINDS.includes(m[1].toUpperCase())) return;
      const kind = m[1].toLowerCase();
      text.value = text.value.slice(m[0].length);
      // drop a leading <br> or empty text that follows the marker
      while (first.children.length && (first.children[0].type === 'break' || (first.children[0].type === 'text' && !first.children[0].value.trim()))) {
        first.children.shift();
      }
      if (!first.children.length) node.children.shift();
      node.data = {
        hName: 'aside',
        hProperties: { className: ['callout', `callout-${kind}`], 'data-label': kind },
      };
    });
  };
}
