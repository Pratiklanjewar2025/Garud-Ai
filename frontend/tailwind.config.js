/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0a0a0b',
        surface: '#121316',
        surfaceHighlight: '#1a1d21',
        primary: '#2563eb',
        primaryHover: '#1d4ed8',
        accent: '#06b6d4',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        textMain: '#f8fafc',
        textMuted: '#94a3b8',
        borderSubtle: '#272a30'
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-primary': '0 0 20px rgba(37, 99, 235, 0.5)',
        'glow-danger': '0 0 20px rgba(239, 68, 68, 0.5)',
      }
    },
  },
  plugins: [],
}
