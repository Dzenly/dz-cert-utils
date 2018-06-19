// .eslintrc is deprecated. http://eslint.org/docs/user-guide/configuring

module.exports = {
  root: true,
  extends: 'airbnb',
  env: {
    browser: true,
    node: true,
    es6: true,
    jest: true,
  },
  rules: {
    strict: 0,

    ['lines-around-comment']: [
      'error',
      {
        beforeLineComment: true,
        allowBlockStart: true,
        allowObjectStart: true,
        allowArrayStart: true,
      },
    ],

    // Otherwise there is syntax errors, without newest babel.
    ['comma-dangle']: [
      'error',
      {
        arrays: 'always-multiline',
        objects: 'always-multiline',
        imports: 'always-multiline',
        exports: 'always-multiline',
        functions: 'never',
      },
    ],

    'no-plusplus': 0,

    'function-paren-newline': 0,

    'import/no-extraneous-dependencies': ['error', { devDependencies: true }],
  },
  globals: {
    Ext: true,
    R: true,
    Glyphs: true,
    Common: true,
    DB: true,
    log: true,
    io: true,
    sails: true,
    Settings: true,
    window: true,
    RV: true,
    Locales: true,
    UTIL: true,
    SMTP: true,
    RM: true,
    MAIL: true,
    LDAP: true,
    IM: true,
    CRON: true,
    CM: true,
    AM: true,
    moment: true,
    Document: true,
    CHARTS: true,
    MAP: true,
    LOG: true,
    IMAP: true,
    SENDMAIL: true,
    smpLog: true,
    test: true,
    it: true,
    beforeEach: true,
    afterEach: true,
    describe: true,
    expect: true,
  },
};
