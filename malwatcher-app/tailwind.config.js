module.exports = {
  content: ['./app/templates/**/*.html'],
  darkMode: 'selector',
  theme: {
    extend: {
      colors: {
        'torchred': {
          50: '#fef2f3',
          100: '#ffe1e4',
          200: '#ffc9cf',
          300: '#fea3ac',
          400: '#fb6e7c',
          500: '#f12d41',
          600: '#e02235',
          700: '#bc192a',
          800: '#9b1926',
          900: '#811b25',
          950: '#46090f',
        },
        'woodsmoke': {
          '50': '#f5f6f6',
          '100': '#e5e7e8',
          '200': '#ced1d3',
          '300': '#acb1b4',
          '400': '#82898e',
          '500': '#676e73',
          '600': '#585e62',
          '700': '#4b4f53',
          '800': '#424548',
          '900': '#3a3c3f',
          '950': '#161718',
        },
      },
    },
  },
  variants: {
    extend: {
      backgroundColor: ['active'],
    },
  },
  plugins: [require('daisyui')],
};