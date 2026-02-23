export default {
  extends: ['@commitlint/config-conventional'],
  plugins: [
    {
      rules: {
        // Reject parenthesized text in the subject (description part).
        // Release Please's parser misinterprets parens as a malformed scope,
        // causing silent release failures.
        'subject-no-parens': ({ subject }) => {
          const hasParens = subject && /\(.+\)/.test(subject);
          return [
            !hasParens,
            'Subject must not contain parenthesized text — Release Please misparses it as a scope. Use dashes or brackets instead.',
          ];
        },
      },
    },
  ],
  rules: {
    'subject-no-parens': [2, 'always'],
  },
};
