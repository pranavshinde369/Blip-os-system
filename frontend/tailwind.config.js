export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        blip: {
          bg:      '#0a0e1a',
          card:    '#111827',
          border:  '#1f2937',
          accent:  '#3b82f6',
          red:     '#ef4444',
          amber:   '#f59e0b',
          green:   '#22c55e',
        },
      },
      animation: {
        'slide-in': 'slideIn 0.35s ease-out',
      },
      keyframes: {
        slideIn: {
          '0%':   { opacity: '0', transform: 'translateY(-8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
