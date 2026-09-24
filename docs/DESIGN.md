# Interface design document

The design separates orientation, investigation and interpretation. The overview explains the product before asking for evidence. The sidebar keeps the four input types visible. The dedicated result workspace reveals detailed evidence only when the user chooses it.

## Information architecture and placement

| Area | Purpose | Placement rationale |
| --- | --- | --- |
| Brand and workspace navigation | Establish location and return path | Persistent left rail on wide screens; compact top navigation on mobile |
| Overview introduction | Explain the task and limitations | First content block before category choices |
| Four category cards | Let users select familiar evidence | Equal visual weight avoids implying a preferred threat diagnosis |
| Category form | Collect only the selected input | Main column with adjacent privacy and preparation guidance |
| Result section controls | Support progressive detail | Immediately after case summary and persistence status |
| Recovery entry | Help someone already affected | Persistent navigation card and a dedicated public page |
| Theme and account | Stable personal controls | Top-right utility area |
| Policy links | Find processing and deletion terms | Footer plus contextual links at submission and registration |

The categories describe evidence, not outcomes. Email accepts pasted text or .eml; a selected file disables the alternate text field to remove ambiguity. File inspection exposes formats progressively. Link entry checks for a complete HTTP or HTTPS URL without embedded credentials.

## Visual system

Use system UI fonts without downloading a font package. Light mode combines an off-white work surface, white cards, dark green text and muted mint accents. The dark sidebar anchors navigation. Dark mode changes the work surface and controls while preserving readable contrast and familiar positions.

A 234-pixel sidebar and a maximum content width of 1370 pixels support desktop scanning. Cards use a four-column grid, reduce to two columns at narrower widths and retain useful tap targets on mobile. At 760 pixels the rail becomes a compact navigation region; the decorative hero illustration is hidden to preserve space. Content must remain usable at 320 pixels and 200 percent zoom; browser verification is a release gate.

The shield illustration is native SVG and CSS. Lucide supplies consistent interface icons. Icons supplement labels; they do not carry meaning alone. A single primary action appears within each form. Destructive actions use explicit wording and a separate confirmation.

## Motion and performance

Motion is the only added animation library. LazyMotion loads the DOM feature set; small opacity and vertical transitions orient the visitor, and a spring interaction lifts category cards slightly. There is no smooth-scroll interception, 3D renderer or autoplay background video.

The shield loader turns horizontally with CSS rotateY around its vertical axis with a fast beginning, gradual deceleration, a brief pause and acceleration into the next cycle. It does not display invented progress percentages. A text notice appears after 15 seconds to explain delays without claiming a completion time. Reduced-motion preferences disable the rotating shield and nonessential transitions.

The result components load separately from the initial page. The measured production JavaScript entry is approximately 109 kB compressed, with a separate result chunk of approximately 5 kB compressed. These are build sizes, not a measured Lighthouse or mobile network score.

## Interaction and accessibility

Use one page heading, descriptive labels, native form controls, visible focus and a skip link to main content. Account and deletion dialogs use native modal behavior, Escape handling and focus restoration. The deletion dialog initially focuses the safe cancellation action. Result section controls expose pressed state and do not pretend to be ARIA tabs without the required keyboard behavior.

Errors explain the action to take, preserve relevant input where possible and avoid displaying internal provider details. Account changes clear private result/history state and cancel pending browser requests. Authentication may remount the evidence form; the guide warns that re-entry may be needed.

No countdown sales tactics, preselected consent, obstructive cancellation, session recordings or hidden marketing opt-ins are included. There are no videos to caption in this release. Add captions and transcripts if video is introduced.

## Design verification

Review the actual deployed build at 320, 390, 768 and 1440 pixels, both themes, keyboard-only operation and reduced motion. Check long filenames, long URLs, empty technical results, browser zoom and mobile navigation. The local build, lint and mocked browser journeys pass. Automated accessibility checks pass on representative light/dark desktop, mobile, account and result screens. Deployed authentication, screen-reader, device and zoom checks remain required.

## Requested animation tools

| Tool | Release choice | Reason |
| --- | --- | --- |
| Motion | Use | Existing transitions, reduced-motion integration and spring card interactions |
| React Spring | Defer | Motion already provides the small physics interactions required here |
| Three.js | Defer | No investigation task currently needs an interactive 3D scene |
| Anime.js | Defer | CSS and Motion cover the current micro interactions |
| Trig.js | Defer | There is no scroll-triggered content requirement |
| Lenis | Defer | Native scroll preserves predictable keyboard and assistive-technology behavior |

On mobile, the Menu button reveals category navigation and recovery. It exposes expanded state and supports Escape. The sidebar remains persistent on desktop. History uses short previews, honest loading/error states and on-demand detail; an unavailable list is never described as an empty account.
