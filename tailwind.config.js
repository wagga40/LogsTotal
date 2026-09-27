/** Used by task css:build (Tailwind standalone CLI). Matches theme in app/templates/base.html.
 *
 * IMPORTANT: the `gray` palette here is rewritten to reference CSS custom
 * properties defined in app/static/themes.css, so `bg-gray-800` etc. become
 * theme-aware automatically. After editing this file you MUST re-run
 * `task css:build` so app/static/vendor/tailwind-built.css is regenerated —
 * otherwise production will ship stale (non-themeable) CSS. The inline Play
 * CDN config in base.html mirrors this mapping for dev mode.
 */

/*
 * Entity-chip colours, enumerated so the build keeps every shade the palettes use
 * even when no template happens to contain one literally. Templates must still
 * write class names out in full (_analytics.html::_chip_classes,
 * _tag_chip.html::tag_classes) — this list is a backstop, not a licence to
 * interpolate: the scanner reads `content` below for *complete* class names, so
 * an assembled one is never there to find. Enumerated rather than a pattern because
 * safelist patterns can't match opacity modifiers (/40 etc.).
 */
const ENTITY_COLORS = [
  "blue",
  "purple",
  "green",
  "cyan",
  "yellow",
  "orange",
  "rose",
  "teal",
  "indigo",
];
const entitySafelist = ENTITY_COLORS.flatMap((c) => [
  `bg-${c}-900/40`,
  `bg-${c}-900/50`,
  `bg-${c}-900/60`,
  `text-${c}-200`,
  `text-${c}-300`,
  `text-${c}-400`,
  `border-${c}-700/40`,
  `border-${c}-700/50`,
  `border-${c}-700/60`,
]);

module.exports = {
  content: ["app/templates/**/*.html"],
  safelist: entitySafelist,
  theme: {
    extend: {
      colors: {
        brand: { 500: "#3b82f6", 600: "#2563eb" },
        gray: {
          50:  "rgb(var(--ui-gray-50)  / <alpha-value>)",
          100: "rgb(var(--ui-gray-100) / <alpha-value>)",
          200: "rgb(var(--ui-gray-200) / <alpha-value>)",
          300: "rgb(var(--ui-gray-300) / <alpha-value>)",
          400: "rgb(var(--ui-gray-400) / <alpha-value>)",
          500: "rgb(var(--ui-gray-500) / <alpha-value>)",
          600: "rgb(var(--ui-gray-600) / <alpha-value>)",
          700: "rgb(var(--ui-gray-700) / <alpha-value>)",
          800: "rgb(var(--ui-gray-800) / <alpha-value>)",
          900: "rgb(var(--ui-gray-900) / <alpha-value>)",
          950: "rgb(var(--ui-gray-950) / <alpha-value>)",
        },
      },
    },
  },
  plugins: [],
};
