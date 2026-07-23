module.exports = {
  content: [
    './app/templates/**/*.html',
    './app/static/js/**/*.js',
  ],
  theme: {
    extend: {
      fontFamily: {
        body: ['Open Sans', 'sans-serif'],
        heading: ['Montserrat', 'sans-serif'],
      },
    },
  },
  daisyui: {
    themes: [
      {
        dmarqlight: {
          // Surface ladder (canvas < section < card) for operational scanability.
          primary: '#272a5f',
          secondary: '#2f9da5',
          accent: '#ff6f3c',
          neutral: '#07071f',
          'base-100': '#ffffff',
          'base-200': '#e5e3ec',
          'base-300': '#bdb9c8',
          'base-content': '#07071f',
          info: '#2f9da5',
          success: '#1f9d67',
          warning: '#d97706',
          error: '#dc2626',
        },
      },
      'dark',
    ],
  },
  plugins: [
    require('daisyui'),
  ],
};
