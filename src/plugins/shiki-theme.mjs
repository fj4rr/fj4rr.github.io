// Code theme limited to the site palette: blue, green, slate. No purple or pink.
export default {
  name: 'fj4rr-terminal',
  type: 'dark',
  colors: { 'editor.background': '#0B1017', 'editor.foreground': '#D5DEE9' },
  tokenColors: [
    { scope: ['comment', 'punctuation.definition.comment'], settings: { foreground: '#5B6B80', fontStyle: 'italic' } },
    { scope: ['keyword', 'storage', 'storage.type', 'keyword.control', 'keyword.operator.new'], settings: { foreground: '#28A9FF' } },
    { scope: ['string', 'string.quoted', 'markup.inline.raw'], settings: { foreground: '#35D98A' } },
    { scope: ['constant.numeric', 'constant.language', 'constant.character'], settings: { foreground: '#7DD3FC' } },
    { scope: ['entity.name.function', 'support.function', 'meta.function-call'], settings: { foreground: '#9BD5FF' } },
    { scope: ['entity.name.type', 'entity.name.class', 'support.type', 'support.class'], settings: { foreground: '#6EE7B7' } },
    { scope: ['variable', 'variable.parameter', 'meta.definition.variable'], settings: { foreground: '#E2E8F0' } },
    { scope: ['variable.other.property', 'support.variable.property', 'entity.name.tag'], settings: { foreground: '#93C5FD' } },
    { scope: ['entity.other.attribute-name'], settings: { foreground: '#A7F3D0' } },
    { scope: ['punctuation', 'meta.brace', 'keyword.operator'], settings: { foreground: '#94A3B8' } },
    { scope: ['markup.heading'], settings: { foreground: '#28A9FF', fontStyle: 'bold' } },
  ],
};
