# Unified design system

Version 2.3 · EVIDENCE cybersecurity evidence investigator

## Design principles

EVIDENCE should feel calm, legible and trustworthy. Every position earns its place: navigation answers “where am I?”, category cards answer “what can I submit?”, result sections answer “why should I believe this?”, and recovery guidance answers “what should I do now?”. The interface never uses urgency, fear, a countdown or a hidden action to create a conversion.

The design system is intended to be implemented as Figma variables and exported as CSS custom properties. Tokens below are the source of truth for product, public pages and future mobile work.

## Color tokens

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| surface.canvas | #F6F8F7 | #101A18 | App background |
| surface.card | #FFFFFF | #182521 | Cards and dialogs |
| surface.soft | #E9F3ED | #23392E | Guidance and status |
| surface.hero | #E0EEE4 | #223B2C | Overview hero |
| ink.primary | #182C29 | #E7F0EB | Main text |
| ink.muted | #586B65 | #A5BAB0 | Supporting text |
| border.default | #DCE5E0 | #33473E | Dividers |
| brand.primary | #12654C | #8EE2B5 | Links and emphasis |
| action.primary | #1C5841 | #B8D99D | Primary button |
| state.error | #AC302D | #FFAAA4 | Error and deletion |
| state.warning | #8A5B04 | #F5CC77 | Caution and uncertainty |
| focus | #196DDA | #96BFFF | Keyboard focus |

Do not use color as the only signal. Pair risk colors with a written label and an icon or explanation. Token values are a starting point; contrast must be checked before claiming WCAG conformance.

## Typography

Use a system stack: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif. The fallback stack avoids a font-license and font-loading dependency.

| Style | Size / line-height | Weight | Use |
| --- | --- | --- | --- |
| Display | 37 / 1.15 | 750 | Hero |
| Heading 1 | 34 / 1.25 | 700 | Page heading |
| Heading 2 | 23 / 1.3 | 700 | Section |
| Heading 3 | 17 / 1.3 | 650 | Card |
| Body | 14 / 1.65 | 400 | Main copy |
| Body small | 12 / 1.6 | 400 | Detail |
| Label | 10 / 1.2 | 750 | Metadata |
| Code | 13 / 1.55 | 400 | URLs and hashes |

## Spacing, icons and motion

Use a 4px base unit with approved values 4, 8, 12, 16, 20, 24, 28, 32, 40 and 48px. Use 8px control radius, 12px card radius and 18px hero radius. Interactive targets are at least 44px.

Lucide React is the approved icon set. ShieldCheck means protection, Link2 means links, Mail means email, FileSearch means files, MessageSquare means texts, History means saved cases, CircleHelp means limitations, AlertCircle means errors and WifiOff means offline. Icons always have visible labels or accessible names.

Motion is the only added animation library. LazyMotion loads the DOM feature set. Small opacity and vertical transitions orient the visitor; a spring lifts category cards slightly. The shield loader uses CSS: fast rotation, gradual deceleration, a short pause and acceleration into the next cycle. Reduced-motion preferences disable nonessential motion. No smooth-scroll hijacking, 3D canvas, autoplay video or scroll-linked effects are in the v2.3 baseline.

## Component contracts

Buttons have a clear verb, a 44px target and disabled state. Inputs have labels, examples, validation and an aria-describedby relationship. Dialogs support Escape and focus restoration. State messages include an icon, heading, explanation and next action. Empty states do not look like errors.

## Figma handoff

Create Figma variables named after these tokens, variants for light and dark, and states for default, hover, focus, disabled and error. Export icons as SVG without embedded fonts. Annotate every asset with its source and license. Mobile developers consume token JSON rather than sampling screenshots.

## Token handoff file

The separate design-tokens.json file contains light and dark colour tokens matching the implemented CSS variables. It is a handoff snapshot; workspace.css remains the runtime source. Keep both synchronized. Import the values into Figma variables if using Figma; no Figma project has been created or published by this update. Preserve semantic names when adapting to a later mobile client.
