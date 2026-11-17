// Small HTML post-processing for long-form reports:
//  - wraps tables so they scroll horizontally on phones
//  - marks mermaid code blocks for the client-side renderer
//  - makes images lazy and zoomable
//  - adds a hover anchor link to h2/h3 headings
function walk(node, parent, fn) {
  fn(node, parent);
  if (node.children) [...node.children].forEach((c) => walk(c, node, fn));
}

export default function rehypeEnhance() {
  return (tree) => {
    walk(tree, null, (node, parent) => {
      if (node.type !== 'element' || !parent) return;
      if (node.tagName === 'table') {
        const idx = parent.children.indexOf(node);
        parent.children[idx] = {
          type: 'element',
          tagName: 'div',
          properties: { className: ['table-wrap'], tabIndex: 0, role: 'region', ariaLabel: 'Scrollable table' },
          children: [node],
        };
      }
      if (node.tagName === 'pre') {
        const code = node.children?.find((c) => c.tagName === 'code');
        const cls = code?.properties?.className || [];
        if (cls.includes('language-mermaid')) {
          node.properties = { ...node.properties, className: ['mermaid-src'] };
        }
      }
      if (node.tagName === 'code' && parent.tagName !== 'pre') {
        const t = node.children?.[0]?.type === 'text' ? node.children[0].value : '';
        if (/^[0-9a-f]{32,128}$/i.test(t)) node.properties = { ...node.properties, className: ['hash'] };
      }
      if (node.tagName === 'img') {
        node.properties = { ...node.properties, loading: 'lazy', decoding: 'async', 'data-zoom': '' };
      }
      if ((node.tagName === 'h2' || node.tagName === 'h3') && node.properties?.id) {
        node.children.push({
          type: 'element',
          tagName: 'a',
          properties: { className: ['h-anchor'], href: `#${node.properties.id}`, ariaLabel: 'Link to this section' },
          children: [{ type: 'text', value: '#' }],
        });
      }
    });
  };
}
